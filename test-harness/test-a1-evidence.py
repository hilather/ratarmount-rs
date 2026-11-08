#!/usr/bin/env python3
"""Regression: native A1 evidence must survive real libtest nesting and refusals.

These synthetic controls do not replace `a1-evidence.py mutations` on a real
uncaptured transcript or native filesystem execution.
"""

import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("a1_evidence", Path(__file__).with_name("a1-evidence.py"))
EVIDENCE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EVIDENCE)


def summary(count, filtered=37):
    return (f"test result: ok. {count} passed; 0 failed; 0 ignored; 0 measured; "
            f"{filtered} filtered out; finished in 0.01s\n")


def transcript(profile, *, optional_skips=False, partial=False):
    manifest = EVIDENCE.MANIFESTS[profile]
    optional = EVIDENCE.OPTIONAL_SUBGROUPS.get(profile, {})
    text = "    Finished `test` profile [unoptimized + debuginfo]\n"
    for family in (EVIDENCE.CORE, {name: groups for name, groups in manifest.items() if name not in EVIDENCE.CORE}):
        text += f"\n     Running unittests src/lib.rs (target/debug/deps/native-fixture)\nrunning {len(family)} tests\n"
        for name, groups in sorted(family.items()):
            text += f"test {name} ... "  # Markers really can share this prefix's line.
            skipped = next((group for group, parent in EVIDENCE.LOCAL_FIXTURES.items()
                            if partial and parent == name), None)
            if skipped:
                text += f"A1_OPTIONAL_FIXTURE_SKIP {skipped} RRS_A1_EXT4_ROOT root=None cause=root is unset\nok\n"
                continue
            mode = "optional" if profile == "local-linux-partial" else "required"
            for group in EVIDENCE.FIXTURE_ROOTS.get(name, ()):
                text += f"A1_FIXTURE_ROOT {group} {EVIDENCE.ROOT_VARIABLES[group]} mode={mode} root='/owned' snapshot=Known\n"
            if name == EVIDENCE.LOCK_PARENT:
                text += "A1_LOCK_PARENT_BEGIN\nengine: SQLite native fixture\n"
                for role in EVIDENCE.LOCK_ROLES:
                    text += (f"\nrunning 1 test\ntest {name} ... A1_LOCK_CHILD_BEGIN {role}\n"
                             f"A1_LOCK_CHILD_COMPLETE {role}\nok\n\n" + summary(1))
            for group, parent in optional.items():
                if parent == name:
                    text += (f"A1_OPTIONAL_SUBGROUP_SKIP {group} {EVIDENCE.OPTIONAL_SKIP_CAUSES[group]}\n"
                             if optional_skips else f"A1_OPTIONAL_SUBGROUP_COMPLETE {group}\n")
            for group in groups:
                text += f"A1_GROUP_COMPLETE {group}\n"
            text += f"A1_TEST_COMPLETE {name}\nok\n"
        text += "\n" + summary(len(family))
    return text


class TranscriptControls(unittest.TestCase):
    def reject(self, text, diagnostic, profile="strict-linux", code=0):
        with self.assertRaisesRegex(EVIDENCE.EvidenceError, diagnostic):
            EVIDENCE.check(text, profile, code)

    def test_regression_fixed_full_names_counts_and_subgroup_matrix(self):
        for profile, parents, groups in (("strict-linux", 14, 18), ("strict-macos", 14, 16),
                                         ("strict-windows", 13, 17)):
            manifest = EVIDENCE.MANIFESTS[profile]
            self.assertEqual(len(manifest), parents)
            self.assertEqual(sum(map(len, manifest.values())), groups)
            self.assertTrue(all(name.startswith(("native_fs::tests::regression_235_part2_a1_",
                                                 "checked_open::native_fs::")) for name in manifest))
        self.assertEqual(set(EVIDENCE.CORE), {
            "native_fs::tests::regression_235_part2_a1_identity_domains",
            "native_fs::tests::regression_235_part2_a1_absent_capability_pending",
        })
        self.assertEqual(set(EVIDENCE.OPTIONAL_SUBGROUPS["strict-windows"]),
                         {"windows_acl_denial", "windows_list_denial"})
        self.assertEqual(set(EVIDENCE.OPTIONAL_SUBGROUPS["strict-macos"]), {"macos_acl_denial"})

    def test_regression_valid_strict_transcripts(self):
        for profile in ("strict-linux", "strict-macos", "strict-windows"):
            with self.subTest(profile=profile):
                result = EVIDENCE.check(transcript(profile), profile, 0)
                self.assertEqual(result["result"], "NATIVE_EVIDENCE_COMPLETE")
                self.assertEqual(result["lock_children"], 0 if profile == "strict-windows" else 6)

    def test_regression_actual_prefix_interleaving_and_crlf(self):
        text = transcript("strict-linux")
        self.assertIn("... A1_LOCK_CHILD_BEGIN", text)
        result = EVIDENCE.check(text.replace("\n", "\r\n"), "strict-linux", 0)
        self.assertEqual(result["parent_statuses"], 14)
        self.assertEqual(result["parent_completions"], 14)
        EVIDENCE.check(text.replace("\nok\n", "\n\x1b[32mok\x1b[0m\n"), "strict-linux", 0)
        EVIDENCE.check(text.replace("engine: SQLite native fixture\n", "engine: metadata query finished ok\n"),
                       "strict-linux", 0)

    def test_regression_empty_wrong_filter_and_zero_tests(self):
        self.reject("", "empty transcript")
        self.reject("running 0 tests\n" + summary(0), "zero tests")
        self.reject("running 2 tests\ntest wrong_filter ... ok\n", "unknown parent test")

    def test_regression_missing_parent_and_unknown_parent(self):
        text = transcript("strict-linux")
        first = next(iter(EVIDENCE.CORE))
        self.reject(text.replace("test " + first + " ... ", "test unrelated_test ... ", 1), "unknown parent test")
        index_start = text.index("running 12 tests")
        self.reject(text[:index_start], "missing parent harness")
        block = (f"test {first} ... A1_GROUP_COMPLETE core.identity_domains\n"
                 f"A1_TEST_COMPLETE {first}\nok\n")
        self.assertIn(block, text)
        self.reject(text.replace(block, "", 1), "libtest summary/count mismatch")

    def test_regression_duplicate_parent_status_and_completion(self):
        text = transcript("strict-linux")
        names = sorted(EVIDENCE.CORE)
        self.reject(text.replace("test " + names[1] + " ... ", "test " + names[0] + " ... ", 1), "duplicate parent test")
        marker = "A1_TEST_COMPLETE " + names[0]
        self.reject(text.replace(marker, marker + "\n" + marker, 1), "duplicate parent completion")

    def test_regression_missing_required_subgroup(self):
        text = EVIDENCE.remove_marker(transcript("strict-linux"), "A1_GROUP_COMPLETE", "linux.tmpfs_names")
        self.reject(text, "missing required group: linux.tmpfs_names")

    def test_regression_preassertion_fixture_observation_is_not_completion(self):
        name = EVIDENCE.LINUX_MODULE + EVIDENCE.PREFIX + "linux_tmpfs"
        text = EVIDENCE.remove_marker(transcript("strict-linux"), "A1_TEST_COMPLETE", name)
        text = text.replace("test " + name + " ... ", "test " + name + " ... "
                            "A1_FIXTURE_ROOT linux.tmpfs RRS_A1_TMPFS_ROOT mode=required root='/configured' snapshot=Known\n", 1)
        self.reject(text, "missing parent completion: " + name)

    def test_regression_duplicate_group(self):
        text = transcript("strict-linux")
        self.reject(text.replace("A1_GROUP_COMPLETE linux.tmpfs_names", "A1_GROUP_COMPLETE linux.tmpfs_names\n" * 2),
                    "duplicate group completion")

    def test_regression_skipped_required_facility(self):
        text = transcript("local-linux-partial", partial=True)
        self.reject(text, "required fixture skipped: linux.ext4_casefold, linux.ext4_sensitive")

    def test_regression_unknown_skip_text_and_unknown_named_skip(self):
        text = transcript("strict-linux")
        self.reject(text + "skip: no filesystem fixture\n", "unrecognized skip text")
        self.reject(text + "skipping required facility\n", "unrecognized skip text")
        self.reject(text.replace("A1_GROUP_COMPLETE linux.tmpfs_names",
                                 "A1_OPTIONAL_FIXTURE_SKIP mystery cause=unknown"), "unknown fixture skip")

    def test_regression_failed_panicked_and_nonzero_harness(self):
        text = transcript("strict-linux")
        self.reject(text, "command failed: exit code 101", code=101)
        self.reject(text + "test result: FAILED\n", "failed or panicked harness")
        self.reject(text + "thread 'fixture' panicked at assertion\n", "failed or panicked harness")

    def test_regression_truncated_transcript_and_missing_status(self):
        text = transcript("strict-linux")
        self.reject(text[:text.rfind("test result: ok.")], "truncated transcript")
        self.reject(text.replace("\nok\n\ntest result: ok. 1", "\n\ntest result: ok. 1", 1),
                    "truncated test status before summary")

    def test_regression_forged_child_only_parent_success(self):
        text = transcript("strict-linux")
        role = EVIDENCE.LOCK_ROLES[0]
        text = text.replace("A1_LOCK_CHILD_COMPLETE " + role,
                            "A1_LOCK_CHILD_COMPLETE " + role + "\nA1_TEST_COMPLETE " + EVIDENCE.LOCK_PARENT, 1)
        self.reject(text, "child attribution cannot mint parent success")

    def test_regression_six_child_successes_do_not_complete_parent(self):
        text = EVIDENCE.remove_marker(transcript("strict-linux"), "A1_TEST_COMPLETE", EVIDENCE.LOCK_PARENT)
        self.assertEqual(text.count("A1_LOCK_CHILD_COMPLETE "), 6)
        self.reject(text, "missing parent completion: " + EVIDENCE.LOCK_PARENT)

    def test_regression_child_sequence_and_raw_alias_close_are_required(self):
        text = transcript("strict-linux")
        self.reject(text.replace("raw_alias_close_released", "after_rollback_released"), "wrong child role/sequence")
        text = EVIDENCE.remove_marker(text, "A1_LOCK_CHILD_COMPLETE", "raw_alias_close_released")
        self.reject(text, "missing child role completion")

    def test_regression_absent_real_allocated_8dot3_group(self):
        text = EVIDENCE.remove_marker(transcript("strict-windows"), "A1_GROUP_COMPLETE", "windows.allocated_8dot3")
        self.reject(text, "missing required group: windows.allocated_8dot3", "strict-windows")

    def test_regression_allowed_optional_acl_skips(self):
        for profile in ("strict-macos", "strict-windows"):
            with self.subTest(profile=profile):
                result = EVIDENCE.check(transcript(profile, optional_skips=True), profile, 0)
                self.assertEqual(set(result["optional_subgroups"]), set(EVIDENCE.OPTIONAL_SUBGROUPS[profile]))

    def test_regression_optional_skip_cannot_substitute_for_required_group(self):
        text = transcript("strict-windows").replace("A1_GROUP_COMPLETE windows.allocated_8dot3",
                 "A1_OPTIONAL_SUBGROUP_SKIP windows.allocated_8dot3 alias missing")
        self.reject(text, "forbidden optional subgroup", "strict-windows")
        text = transcript("strict-windows").replace("A1_GROUP_COMPLETE windows.native_errors", "")
        self.reject(text, "missing required group: windows.native_errors", "strict-windows")
        text = transcript("strict-macos", optional_skips=True).replace(
            "root bypasses permission denial", "required APFS fixture unavailable")
        self.reject(text, "forbidden optional subgroup cause", "strict-macos")

    def test_regression_local_partial_never_native_pass(self):
        result = EVIDENCE.check(transcript("local-linux-partial", partial=True), "local-linux-partial", 0)
        self.assertEqual(result["result"], "LOCAL_PARTIAL_EVIDENCE")
        self.assertEqual((result["parent_completions"], result["required_groups_completed"]), (12, 13))
        self.assertEqual(result["optional_fixture_skips"], ["linux.ext4_casefold", "linux.ext4_sensitive"])

    def test_regression_strict_profile_cannot_upgrade_optional_run(self):
        text = transcript("strict-linux").replace("mode=required", "mode=optional")
        self.reject(text, "strict profile requires required fixture mode")
        self.assertEqual(EVIDENCE.check(text, "local-linux-partial", 0)["result"], "LOCAL_PARTIAL_EVIDENCE")

    def test_regression_required_mode_observation_cannot_be_omitted(self):
        text = re.sub(r"A1_FIXTURE_ROOT[^\r\n]*", "", transcript("strict-linux"))
        self.reject(text, "missing fixture root/mode observation")

    def test_regression_real_log_mutation_interface_uses_same_partial_profile(self):
        text = transcript("local-linux-partial", partial=True)
        with tempfile.TemporaryDirectory() as directory:
            result = EVIDENCE.validate_mutations(text, 0, Path(directory) / "mutations")
        self.assertEqual(len(result["mutations"]), 9)
        self.assertTrue(all(row["rejected"] for row in result["mutations"].values()))
        self.assertEqual(result["baseline"]["result"], "LOCAL_PARTIAL_EVIDENCE")

    def test_regression_strict_profiles_have_no_caller_manifest_override(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
            EVIDENCE.main(["check", "--profile", "strict-linux", "--log", "unused", "--exit-code", "0",
                           "--manifest", "weakened.json"])
        self.assertEqual(error.exception.code, 2)
        with self.assertRaises(TypeError):
            EVIDENCE.check("", "strict-linux", 0, manifest={})
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            EVIDENCE.main(["mutations", "--profile", "strict-linux", "--log", "unused", "--exit-code", "0",
                           "--output-dir", "unused"])

    def test_regression_root_failure_control_refuses_fallback_success(self):
        test = EVIDENCE.LINUX_MODULE + EVIDENCE.PREFIX + "linux_tmpfs"
        success = f"running 1 test\ntest {test} ... A1_GROUP_COMPLETE linux.tmpfs_identity\nA1_TEST_COMPLETE {test}\nok\n" + summary(1)
        with self.assertRaisesRegex(EVIDENCE.EvidenceError, "substituted successful fixture"):
            EVIDENCE.validate_root_control(success, 0, "RRS_A1_TMPFS_ROOT", "linux.tmpfs", test, "/missing-root", True)

    def test_regression_root_failure_controls_name_root_and_exact_test(self):
        test = EVIDENCE.LINUX_MODULE + EVIDENCE.PREFIX + "linux_tmpfs"
        failure = (f"running 1 test\ntest {test} ... \nthread 'fixture' panicked at test\n"
                   'A1_REQUIRED_FIXTURE_FAILURE linux.tmpfs RRS_A1_TMPFS_ROOT root=Some("/missing-root") cause=root metadata\n'
                   "FAILED\ntest result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 7 filtered out; finished in 0.01s\n")
        EVIDENCE.validate_root_control(failure, 101, "RRS_A1_TMPFS_ROOT", "linux.tmpfs", test, "/missing-root", True)
        with self.assertRaisesRegex(EVIDENCE.EvidenceError, "did not name configured root"):
            EVIDENCE.validate_root_control(failure, 101, "RRS_A1_TMPFS_ROOT", "linux.tmpfs", test, "/different-root", True)
        with self.assertRaisesRegex(EVIDENCE.EvidenceError, "exact target test"):
            EVIDENCE.validate_root_control(failure.replace(test, "unrelated"), 101, "RRS_A1_TMPFS_ROOT", "linux.tmpfs", test, "/missing-root", True)
        with self.assertRaisesRegex(EVIDENCE.EvidenceError, "wrong cause"):
            EVIDENCE.validate_root_control(failure, 101, "RRS_A1_TMPFS_ROOT", "linux.tmpfs", test, "/missing-root", True,
                                           "cause=wrong filesystem:")

    def test_regression_optional_root_control_requires_skip_without_completion(self):
        test = EVIDENCE.LINUX_MODULE + EVIDENCE.PREFIX + "linux_tmpfs"
        skipped = (f"running 1 test\ntest {test} ... "
                   'A1_OPTIONAL_FIXTURE_SKIP linux.tmpfs RRS_A1_TMPFS_ROOT root=Some("/missing-root") cause=root metadata: absent\n'
                   "ok\n" + summary(1))
        EVIDENCE.validate_root_control(skipped, 0, "RRS_A1_TMPFS_ROOT", "linux.tmpfs", test, "/missing-root", False,
                                       "cause=root metadata:")
        with self.assertRaisesRegex(EVIDENCE.EvidenceError, "optional root control"):
            EVIDENCE.validate_root_control(skipped, 101, "RRS_A1_TMPFS_ROOT", "linux.tmpfs", test, "/missing-root", False)


def reseal(record):
    for stream in ("stdout", "stderr"):
        record[stream + "_sha256"] = EVIDENCE.digest(record[stream].encode())


def reseal_cell(cell):
    for record in cell["runs"].values():
        reseal(record)
    cell["combined_sha256"] = EVIDENCE.digest("".join(
        cell["runs"][package]["stdout"] for package in EVIDENCE.PACKAGES[:2]).encode())


class EngineRunner:
    """Owned ELF data fixtures and mocked processes, never a native-support claim.

    Only process creation is mocked. The shipped command, package, graph,
    artifact, listing, runtime and transcript validators all run normally.
    """
    source = {"source_sha256": "1" * 64, "lock_sha256": "2" * 64,
              "head": "3" * 40, "head_tree": "4" * 40,
              "lock_packages": [
                  {"name": "libsqlite3-sys", "version": "0.30.1", "source": "registry+https://github.com/rust-lang/crates.io-index"},
                  {"name": "rusqlite", "version": "0.32.1", "source": "registry+https://github.com/rust-lang/crates.io-index"},
              ]}
    target = "x86_64-unknown-linux-gnu"

    def __init__(self):
        self.calls = []
        self.executables = {}
        self.mutate = lambda name, record: None

    def metadata(self, engine):
        packages, nodes = [], []
        for name in EVIDENCE.PACKAGES:
            package_id = f"path+file://{ROOT / name}#{name}@1.0.0"
            packages.append({"name": name, "id": package_id, "version": "1.0.0", "source": None,
                             "manifest_path": str(ROOT / name / "Cargo.toml"),
                             "targets": [{"name": name.replace("-", "_"), "kind": ["lib"], "crate_types": ["lib"],
                                          "src_path": str(ROOT / name / "src/lib.rs")}]})
        for lock in self.source["lock_packages"]:
            packages.append({**lock, "id": lock["source"] + "#" + lock["name"] + "@" + lock["version"]})
        ids = {package["name"]: package["id"] for package in packages}
        for package in packages:
            name = package["name"]
            features = ["bundled"] if name in ("rusqlite", "libsqlite3-sys") else []
            if engine == "sqlcipher":
                if name in ("rusqlite", "libsqlite3-sys"):
                    features += ["bundled-sqlcipher", "bundled-sqlcipher-vendored-openssl"]
                elif name == EVIDENCE.PACKAGES[2]:
                    features += ["sqlcipher"]
            dependencies = ([ids["libsqlite3-sys"]] if name == "rusqlite" else
                            [ids["rusqlite"], ids[EVIDENCE.PACKAGES[0]]] if name == EVIDENCE.PACKAGES[1] else
                            [ids["rusqlite"], ids[EVIDENCE.PACKAGES[0]], ids[EVIDENCE.PACKAGES[1]]] if name == EVIDENCE.PACKAGES[2] else [])
            nodes.append({"id": package["id"], "features": features, "dependencies": dependencies})
        return {"workspace_root": str(ROOT), "packages": packages, "resolve": {"nodes": nodes},
                "workspace_members": [ids[name] for name in EVIDENCE.PACKAGES]}

    def build_output(self, engine, env, selected):
        metadata = self.metadata(engine)
        nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
        events = []
        directory = Path(env["CARGO_TARGET_DIR"]) / self.target / "debug/deps"
        directory.mkdir(parents=True)
        for index, package in enumerate(metadata["packages"]):
            test = package["name"] in selected
            target = package.get("targets", [{"name": package["name"].replace("-", "_"), "kind": ["lib"],
                                              "crate_types": ["lib"], "src_path": "/locked/dependency/src/lib.rs"}])[0]
            executable = directory / (target["name"] + f"-{index:016x}") if test else None
            if executable is not None:
                data = bytearray(64)
                data[:7] = b"\x7fELF\x02\x01\x01"
                data[16:18] = (3).to_bytes(2, "little")
                data[18:20] = (62).to_bytes(2, "little")
                executable.write_bytes(data + (engine + package["name"]).encode())
                executable.chmod(0o700)
                self.executables[str(executable)] = (engine, package["name"])
            events.append({"reason": "compiler-artifact", "package_id": package["id"], "target": target,
                           "profile": {"test": test, "opt_level": "0", "debug_assertions": True},
                           "executable": str(executable) if executable is not None else None,
                           "filenames": [str(executable)] if executable is not None else [],
                           "features": nodes[package["id"]]["features"]})
        events.append({"reason": "build-finished", "success": True})
        return "".join(json.dumps(event) + "\n" for event in events)

    def observations(self, text, engine, executable, env):
        for index, role in enumerate(("parent", *EVIDENCE.LOCK_ROLES)):
            record = {"role": role, "version": "3.46.1", "source_id": "2024 native SQLite source 1234",
                      "cipher_version": "4.6.1 community" if engine == "sqlcipher" else None,
                      "engine": engine, "expected": env.get("RATARMOUNT_TEST_SQLITE_BACKEND"),
                      "strict": env.get("RRS_A1_STRICT_ENGINE") == "1", "pid": 1000 + index,
                      "executable": executable, "sha256": EVIDENCE.digest(Path(executable).read_bytes())}
            marker = "A1_LOCK_PARENT_BEGIN" if role == "parent" else "A1_LOCK_CHILD_BEGIN " + role
            text = text.replace(marker + "\n", marker + "\nENGINE_OBSERVATION " + json.dumps(record) + "\n", 1)
        return text

    def lock_transcript(self):
        name = EVIDENCE.LOCK_PARENT
        text = f"running 1 test\ntest {name} ... A1_LOCK_PARENT_BEGIN\n"
        for role in EVIDENCE.LOCK_ROLES:
            text += (f"running 1 test\ntest {name} ... A1_LOCK_CHILD_BEGIN {role}\n"
                     f"A1_LOCK_CHILD_COMPLETE {role}\nok\n" + summary(1))
        return text + f"A1_GROUP_COMPLETE unix.lock_parent\nA1_TEST_COMPLETE {name}\nok\n" + summary(1)

    def binary_output(self, command, env, label):
        executable, arguments = command[0], command[1:]
        engine, package = self.executables[executable]
        if "--list" in arguments:
            names = (sorted(EVIDENCE.CORE) if package == EVIDENCE.PACKAGES[0] else
                     sorted(set(EVIDENCE.MANIFESTS["strict-linux"]) - EVIDENCE.CORE.keys())
                     if package == EVIDENCE.PACKAGES[1] else []) if arguments[0] == EVIDENCE.PREFIX else [arguments[0]]
            return "".join(name + ": test\n" for name in names) + f"\n{len(names)} tests, 0 benchmarks\n", 0
        if label == "old-root-negative":
            test = arguments[0]
            return (f"running 1 test\ntest {test} ... \n"
                    f'A1_REQUIRED_FIXTURE_FAILURE linux.tmpfs RRS_A1_TMPFS_ROOT root=Some("{env["RRS_A1_TMPFS_ROOT"]}") '
                    'cause=root must be owned by this uid and private (mode 0700)\n'
                    "FAILED\ntest result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 1 filtered out; finished in 0.01s\n"), 101
        if arguments[0] == EVIDENCE.LOCK_PARENT:
            backend = env.get("RATARMOUNT_TEST_SQLITE_BACKEND")
            diagnostic = ("strict engine requires RATARMOUNT_TEST_SQLITE_BACKEND" if backend is None and env.get("RRS_A1_STRICT_ENGINE") == "1" else
                          "invalid RATARMOUNT_TEST_SQLITE_BACKEND" if backend not in (None, *EVIDENCE.ENGINES) else
                          "SQLite engine differs from requested backend" if backend not in (None, engine) else None)
            if diagnostic:
                return (f"running 1 test\ntest {EVIDENCE.LOCK_PARENT} ... \nthread 'engine' panicked at {diagnostic}\n"
                        "FAILED\ntest result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 1 filtered out; finished in 0.01s\n"), 101
            return self.observations(self.lock_transcript(), engine, executable, env), 0
        if arguments == EVIDENCE.A1_RUN_ARGS:
            text = transcript("strict-linux")
            split = text.index("\n     Running unittests", text.index("\n     Running unittests") + 1)
            text = text[:split] if package == EVIDENCE.PACKAGES[0] else text[split:]
            return self.observations(text, engine, executable, env), 0
        return f"running 1 test\ntest {arguments[0]} ... ok\n" + summary(1), 0

    def __call__(self, command, env, output, name, *, merged=False, timeout=600):
        self.calls.append((command, merged))
        # Derive compiled features from actual argv, independently of the label.
        engine = "sqlcipher" if "ratarmount-formats-sqlar/sqlcipher" in command else "stock"
        status = 0
        if command == ["rustc", "-vV"]:
            text = "rustc 1.90.0\nhost: " + self.target + "\n"
        elif "metadata" in command:
            text = json.dumps(self.metadata(engine))
        elif "--no-run" in command:
            selected = [command[index + 1] for index, token in enumerate(command) if token == "-p"]
            text = self.build_output(engine, env, selected)
        elif "tree" in command:
            text = "libsqlite3-sys v0.30.1\nratarmount-index v1.0.0\nratarmount-formats-sqlar v1.0.0\n"
            if engine == "sqlcipher":
                text += ('libsqlite3-sys feature "bundled-sqlcipher-vendored-openssl"\n'
                         'rusqlite feature "bundled-sqlcipher-vendored-openssl"\n'
                         'ratarmount-formats-sqlar feature "sqlcipher"\n')
        else:
            text, status = self.binary_output(command, env, name)
        record = {"argv": list(command), "cwd": str(ROOT), "status": status, "timed_out": False,
                  "merged": merged, "env": {key: env[key] for key in EVIDENCE.RECORDED_ENV if key in env},
                  "stdout": text, "stderr": ""}
        self.mutate(name, record)
        reseal(record)
        for stream in ("stdout", "stderr"):
            (output / (name + "." + stream)).write_bytes(record[stream].encode())
        EVIDENCE.save_json(output / (name + ".json"), record)
        return record


class EngineProtocolControls(unittest.TestCase):
    def setUp(self):
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory(prefix="a1-engine-contract-")))
        self.output = self.directory / "engines"
        self.runner = EngineRunner()
        self.enterContext(mock.patch.object(EVIDENCE, "capture", side_effect=self.runner))
        self.enterContext(mock.patch.object(EVIDENCE, "source_identity", return_value=copy.deepcopy(self.runner.source)))
        self.enterContext(mock.patch.object(EVIDENCE.platform, "machine", return_value="x86_64"))
        self.enterContext(mock.patch.object(EVIDENCE.sys, "platform", "linux"))
        self.enterContext(mock.patch.dict(os.environ, {"RRS_A1_TMPFS_ROOT": "/owned/tmpfs", "RRS_A1_EXT4_ROOT": "/owned/ext4"}))

    def baseline(self):
        EVIDENCE.build_engines(self.output)
        EVIDENCE.run_engines(self.output)
        cells = EVIDENCE.load_engines(self.output)
        self.assertEqual(EVIDENCE.verify_matrix(cells, executed=True)["engines"], list(EVIDENCE.ENGINES))
        return cells

    def reject(self, cells, diagnostic):
        self.runner.calls.clear()
        with self.assertRaisesRegex(EVIDENCE.EvidenceError, diagnostic):
            EVIDENCE.verify_matrix(cells, executed=True)
        self.assertEqual(self.runner.calls, [], "offline verifier executed an unverified artifact")

    def edit_observation(self, cell, change):
        record = cell["runs"][EVIDENCE.PACKAGES[1]]
        def edit(match):
            value = json.loads(match[1])
            return "ENGINE_OBSERVATION " + json.dumps(change(value))
        record["stdout"] = re.sub(r"ENGINE_OBSERVATION ([^\r\n]+)", edit, record["stdout"])
        reseal_cell(cell)

    def test_regression_validators_reject_failures_but_accept_canonical_zero_failure_summaries(self):
        """Regression: canonical 0 failed summaries pass without hiding failures.

        Each negative reseals one stdout or status-field edit in a valid matrix.
        """
        cells = self.baseline()
        line = summary(1).removesuffix("\n")
        diagnostics = ("Error: io", "thread 'x' panicked at y", "skip: z", "FAILED", "panic: x", "failures: x")
        contaminated = [line + " " + text for text in diagnostics]
        contaminated += [line + "\n" + text for text in
                         ("Error: io", "thread 'x' panicked at y", "Skipping: z", "FAILED")]
        contaminated += ["Error: io " + line]
        contaminated += [line.replace("0.01s", timing) for timing in ("0.1s", "0.001s", "1s")]
        contaminated += [line + separator + text for separator in ("\r", "\v", "\u2028")
                         for text in ("Error: io", "fixture note")]
        contaminated += ["Error: io" + separator + line for separator in ("\r", "\v", "\u2028")]

        def select(matrix, index, group):
            cell = matrix[index]
            return cell["environment_controls"]["ordinary"] if group is None else cell["sqlar_groups"][group]["run"]

        for index in (0, 1):
            for group in (*EVIDENCE.SQLAR_GROUPS, None):
                self.assertIn("0 failed;", select(cells, index, group)["stdout"])
                for ending in ("CRLF", "EOF"):
                    with self.subTest(index=index, group=group, ending=ending):
                        positive = copy.deepcopy(cells)
                        record = select(positive, index, group)
                        text = (record["stdout"].replace("\n", "\r\n") if ending == "CRLF"
                                else record["stdout"].removesuffix("\n"))
                        record["stdout"] = text
                        reseal(record)
                        self.assertEqual(EVIDENCE.verify_matrix(positive, executed=True)["engines"], list(EVIDENCE.ENGINES))
                        self.assertEqual(record["stdout"], text, "validator rewrote raw evidence")
                failure = ("ordinary/no-env lock control failed" if group is None
                           else "mandatory behavior failed/ignored/skipped")
                structure = ("ordinary/no-env parent/child status mismatch" if group is None
                             else "mandatory behavior did not pass exactly one test")
                identity = ("ordinary/no-env parent/child identity/running/status mismatch" if group is None
                            else structure)
                rows = [(line, changed, failure) for changed in contaminated]
                rows += [
                    ("ok\n", "FAILED\n", failure),
                    ("test result: ok.", "test result: FAILED.", failure),
                    ("0 ignored", "1 ignored", failure),
                    (line, "test result: ok. 1 passed; 0 failed;", failure),
                    (line, "test result: ok. 1 passed;", structure),
                    ("1 passed", "2 passed", structure),
                    ("1 passed", "0 passed", failure),
                    ("37 filtered", "\u0663\u0667 filtered", failure),
                    (line + "\n", "", structure),
                    (line + "\n", (line + "\n") * 2, structure),
                    ("ok\n", "ignored\n", identity),
                ]
                if group is None:
                    rows += [
                        (None, 101, failure),
                        ("test " + EVIDENCE.LOCK_PARENT + " ... ", "test other::test ... ", identity),
                        ("running 1 test\n", "running 2 tests\n", identity),
                        ("running 1 test\n", "", identity),
                    ]
                else:
                    rows += [("running 1 test\n", "running 0 tests\n", "mandatory behavior harness/count")]
                for before, after, diagnostic in rows:
                    positions = (0,)
                    if group is None and before is not None:
                        positions = (0, 1) if before.startswith(("running ", "test " + EVIDENCE.LOCK_PARENT)) else (6, 0)
                    for occurrence in positions:
                        with self.subTest(index=index, group=group, before=before, after=after, occurrence=occurrence):
                            mutated = copy.deepcopy(cells)
                            record = select(mutated, index, group)
                            if before is None:
                                record["status"] = after
                            else:
                                matches = list(re.finditer(re.escape(before), record["stdout"]))
                                self.assertEqual(len(matches), 7 if group is None else 1)
                                match = matches[occurrence]
                                record["stdout"] = record["stdout"][:match.start()] + after + record["stdout"][match.end():]
                            reseal(record)
                            self.reject(mutated, "^" + re.escape(diagnostic) + "$")

    def test_regression_complete_stock_cipher_and_ancillary_zero_boundary(self):
        cells = self.baseline()
        for cell in cells:
            self.assertEqual(cell["ancillary"], "ancillary_sqlar_no_A1_group")
            self.assertEqual(set(cell["sqlar_groups"]), set(EVIDENCE.SQLAR_GROUPS))
            EVIDENCE.list_inventory(cell["lists"][EVIDENCE.PACKAGES[2]], [])
            self.assertEqual(len(EVIDENCE.verify_engine_observations(cell["runs"][EVIDENCE.PACKAGES[1]]["stdout"], cell)), 7)
        builds = [command for command, _ in self.runner.calls if "--no-run" in command]
        self.assertEqual(len(builds), 2)
        for engine, command in zip(EVIDENCE.ENGINES, builds):
            expected = ["flock", "/tmp/muse-cargo.lock", "cargo", "test", "--locked", "--no-run",
                        "--message-format=json", "--lib", "-p", "ratarmount-core", "-p", "ratarmount-index",
                        "-p", "ratarmount-formats-sqlar"]
            if engine == "sqlcipher":
                expected += ["--features", "ratarmount-formats-sqlar/sqlcipher"]
            self.assertEqual(command, expected + ["--target", EngineRunner.target])
        self.assertTrue(all(merged for command, merged in self.runner.calls if command[0] in self.runner.executables))
        result = EVIDENCE.engine_mutations(cells, self.directory / "mutations")
        self.assertEqual(set(result["mutations"]), {"wrong-engine", "missing-feature", "missing-group"})

    def test_regression_runtime_facts_independent_of_engine_labels(self):
        cells = self.baseline()
        mutations = (
            (0, "runtime engine differs", lambda value: {**value, "cipher_version": "4.6.1"}),
            (1, "runtime engine differs", lambda value: {**value, "cipher_version": None}),
            (1, "runtime engine differs", lambda value: {**value, "cipher_version": ""}),
            (1, "runtime engine differs", lambda value: {**value, "cipher_version": None} if value["role"] == EVIDENCE.LOCK_ROLES[2] else value),
            (0, "version/sourceID", lambda value: {**value, "version": ""}),
            (0, "version/sourceID", lambda value: {key: item for key, item in value.items() if key != "version"}),
            (1, "version/sourceID", lambda value: {key: item for key, item in value.items() if key != "source_id"}),
            (1, "version/sourceID", lambda value: {**value, "source_id": " "}),
            (0, "label differs", lambda value: {**value, "engine": "sqlcipher"}),
            (1, "strict/backend environment", lambda value: {**value, "expected": None}),
            (0, "strict/backend environment", lambda value: {**value, "expected": "invalid"}),
            (1, "strict/backend environment", lambda value: {**value, "strict": False}),
            (0, "executable binding", lambda value: {**value, "executable": "/foreign/same-name"}),
            (1, "executable binding", lambda value: {**value, "sha256": "0" * 64}),
            (1, "process identity", lambda value: {**value, "pid": 1000}),
            (1, "engine facts differ", lambda value: {**value, "source_id": "different native source"}
             if value["role"] == EVIDENCE.LOCK_ROLES[0] else value),
            (0, "unrecognized runtime engine role", lambda value: {**value, "role": "unknown"} if value["role"] == "parent" else value),
        )
        for index, diagnostic, change in mutations:
            with self.subTest(index=index, diagnostic=diagnostic):
                mutated = copy.deepcopy(cells)
                self.edit_observation(mutated[index], change)
                self.reject(mutated, diagnostic)
        for duplicate, missing_role in ((False, "parent"), (False, EVIDENCE.LOCK_ROLES[0]), (True, "parent")):
            mutated = copy.deepcopy(cells)
            record = mutated[1]["runs"][EVIDENCE.PACKAGES[1]]
            observation = next(match[0] for match in re.finditer(r"ENGINE_OBSERVATION ([^\r\n]+)\n", record["stdout"])
                               if json.loads(match[1])["role"] == missing_role)
            record["stdout"] = record["stdout"] + observation if duplicate else record["stdout"].replace(observation, "", 1)
            reseal_cell(mutated[1])
            self.reject(mutated, "duplicate runtime engine role" if duplicate else "missing/unrecognized runtime engine role")

    def test_regression_build_features_graph_packages_and_completion(self):
        cells = self.baseline()
        for phase, operation, diagnostic in (
            ("build", lambda record: record["argv"].remove("ratarmount-formats-sqlar/sqlcipher"), "command/package/feature mismatch"),
            ("build", lambda record: record["argv"].remove("ratarmount-formats-sqlar"), "command/package/feature mismatch"),
            ("build", lambda record: record["argv"].remove("ratarmount-core"), "command/package/feature mismatch"),
            ("build", lambda record: record["argv"].remove("ratarmount-index"), "command/package/feature mismatch"),
            ("graph", lambda record: record.update(stdout=""), "rooted engine feature graph"),
            ("graph", lambda record: record.update(stdout=record["stdout"].replace('libsqlite3-sys feature "bundled-sqlcipher-vendored-openssl"', "removed")), "feature graph path"),
            ("build", lambda record: record.update(status=101), "command failed"),
            ("build", lambda record: record.update(stdout=record["stdout"].rsplit('\n', 2)[0] + '\n'), "build-finished"),
            ("build", lambda record: record.update(stdout=record["stdout"].replace('"success": true', '"success": false')), "build-finished"),
            ("build", lambda record: record.update(stdout=record["stdout"] + "{"), "malformed build/metadata JSON"),
        ):
            with self.subTest(phase=phase, diagnostic=diagnostic):
                mutated = copy.deepcopy(cells)
                record = mutated[1]["commands"][phase]
                operation(record)
                reseal(record)
                self.reject(mutated, diagnostic)
        mutated = copy.deepcopy(cells)
        del mutated[1]["commands"]["graph"]
        self.reject(mutated, "extra/missing Cargo invocation")
        mutated = copy.deepcopy(cells)
        mutated[1]["commands"]["second-core-index-build"] = copy.deepcopy(mutated[0]["commands"]["build"])
        self.reject(mutated, "extra/missing Cargo invocation")

    def test_regression_compiled_and_resolved_engine_feature_identity(self):
        cells = self.baseline()
        for index, family, diagnostic in (
            (1, EVIDENCE.PACKAGES[2], "SQLAR artifact missing/unexpected"),
            (1, "libsqlite3-sys", "SQLCipher dependency feature"),
            (0, "rusqlite", "SQLCipher dependency feature"),
        ):
            mutated = copy.deepcopy(cells)
            record = mutated[index]["commands"]["build"]
            events = [json.loads(line) for line in record["stdout"].splitlines()]
            for event in events:
                if family.replace("-", "_") == event.get("target", {}).get("name"):
                    event["features"] = [] if index else ["bundled", "bundled-sqlcipher"]
                    if family == "libsqlite3-sys":
                        event["features"] = ["bundled"]
            record["stdout"] = "".join(json.dumps(event) + "\n" for event in events)
            reseal(record)
            self.reject(mutated, diagnostic)
        for mutation, diagnostic in (
            ("duplicate-engine", "ambiguous locked SQLite engine family"),
            ("lock-version", "lock/packageID engine mismatch"),
            ("package-id", "resolved engine packageID mismatch"),
            ("resolved-feature", "SQLAR resolved feature mismatch"),
        ):
            mutated = copy.deepcopy(cells)
            record = mutated[1]["commands"]["metadata"]
            metadata = json.loads(record["stdout"])
            sqlite = next(package for package in metadata["packages"] if package["name"] == "libsqlite3-sys")
            if mutation == "duplicate-engine":
                metadata["packages"].append({**sqlite, "id": sqlite["id"] + "-foreign", "version": "0.31.0"})
            elif mutation == "lock-version":
                sqlite["version"] = "0.31.0"
            elif mutation == "package-id":
                sqlite["id"] = "foreign-sqlite-packageID"
            else:
                sqlar = next(package for package in metadata["packages"] if package["name"] == EVIDENCE.PACKAGES[2])
                next(node for node in metadata["resolve"]["nodes"] if node["id"] == sqlar["id"])["features"] = []
            record["stdout"] = json.dumps(metadata)
            reseal(record)
            self.reject(mutated, diagnostic)

    def test_regression_artifact_missing_duplicate_foreign_stale_profile_and_hash(self):
        cells = self.baseline()
        for mutation, diagnostic in (
            ("missing-core", "missing required core/index/SQLAR artifact"),
            ("missing-index", "missing required core/index/SQLAR artifact"),
            ("missing-sqlar", "missing required core/index/SQLAR artifact"),
            ("duplicate", "duplicate test artifact"),
            ("foreign-package", "unexpected test artifact packageID"),
            ("foreign-path", "artifact outside exact cell target"),
            ("other-engine-path", "artifact outside exact cell target"),
            ("wrong-source", "source/target/profile mismatch"),
            ("wrong-profile", "source/target/profile mismatch"),
            ("unknown-same-name", "unknown same-name executable artifact"),
        ):
            mutated = copy.deepcopy(cells)
            record = mutated[1]["commands"]["build"]
            events = [json.loads(line) for line in record["stdout"].splitlines()]
            event = events[1]
            if mutation.startswith("missing-"):
                del events[{"missing-core": 0, "missing-index": 1, "missing-sqlar": 2}[mutation]]
            elif mutation == "duplicate":
                events.insert(2, copy.deepcopy(event))
            elif mutation == "foreign-package":
                event["package_id"] = "foreign-same-name-package"
            elif mutation in ("foreign-path", "other-engine-path"):
                event["executable"] = (str(self.directory / Path(event["executable"]).name) if mutation == "foreign-path"
                                       else cells[0]["artifacts"][EVIDENCE.PACKAGES[1]]["path"])
                event["filenames"] = [event["executable"]]
            elif mutation == "wrong-source":
                event["target"]["src_path"] = "/foreign/src/lib.rs"
            elif mutation == "wrong-profile":
                event["profile"]["opt_level"] = "3"
            else:
                event["filenames"] = [str(self.directory / "unknown-same-name")]
            record["stdout"] = "".join(json.dumps(event) + "\n" for event in events)
            reseal(record)
            self.reject(mutated, diagnostic)
        path = Path(cells[1]["artifacts"][EVIDENCE.PACKAGES[1]]["path"])
        original = path.read_bytes()
        for data, diagnostic in ((original + b"replacement", "artifact replaced after enumeration"),
                                 (b"#!/bin/sh\nexit 0\n", "nonnative executable artifact")):
            try:
                path.write_bytes(data)
                self.reject(cells, diagnostic)
            finally:
                path.write_bytes(original)
        with mock.patch.object(EVIDENCE, "source_identity", return_value={**self.runner.source, "lock_sha256": "0" * 64}):
            self.reject(cells, "changed source/lock identity")

    def test_regression_list_inventory_and_independent_sqlar_behavior(self):
        cells = self.baseline()
        for package in EVIDENCE.PACKAGES[:2]:
            for mutation in ("zero", "missing", "extra", "duplicate"):
                with self.subTest(package=package, mutation=mutation):
                    mutated = copy.deepcopy(cells)
                    record = mutated[0]["lists"][package]
                    lines = record["stdout"].splitlines()
                    if mutation == "zero":
                        lines = ["0 tests, 0 benchmarks"]
                    elif mutation == "missing":
                        lines.pop(0)
                    elif mutation == "extra":
                        lines.insert(0, "unknown::test: test")
                    else:
                        lines.insert(0, lines[0])
                    record["stdout"] = "\n".join(lines) + "\n"
                    reseal(record)
                    self.reject(mutated, "duplicate listed test" if mutation == "duplicate" else "missing/extra required listed test")
        for mutation, diagnostic in (("missing-group", "missing mandatory SQLAR behavior"),
                                     ("zero-group", "missing/extra required listed test"),
                                     ("skipped-group", "mandatory behavior failed/ignored/skipped"),
                                     ("status", "command failed"),
                                     ("wrong-name", "mandatory behavior test identity"),
                                     ("ancillary-label", "ancillary relabeled required"),
                                     ("unknown-ancillary", "missing/extra required harness")):
            mutated = copy.deepcopy(cells)
            cell = mutated[1]
            group = cell["sqlar_groups"][EVIDENCE.SQLAR_GROUPS[2]]
            if mutation == "missing-group":
                del cell["sqlar_groups"][EVIDENCE.SQLAR_GROUPS[2]]
            elif mutation == "zero-group":
                group["list"]["stdout"] = "0 tests, 0 benchmarks\n"
            elif mutation == "skipped-group":
                group["run"]["stdout"] += "skip: encrypted branch unavailable\n"
            elif mutation == "status":
                group["run"]["status"] = 1
            elif mutation == "wrong-name":
                group["run"]["stdout"] = group["run"]["stdout"].replace(EVIDENCE.SQLAR_GROUPS[2], "unknown::test")
            elif mutation == "ancillary-label":
                cell["ancillary"] = "required"
            else:
                cell["lists"]["unknown-ancillary"] = cell["lists"][EVIDENCE.PACKAGES[2]]
            for record in group.values():
                reseal(record)
            self.reject(mutated, diagnostic)

    def test_regression_full_raw_harnesses_are_not_filtered_or_made_optional(self):
        cells = self.baseline()
        for mutation, diagnostic in (("ancillary-zero", "zero tests in harness"),
                                     ("parent", "missing parent completion"),
                                     ("child", "missing child role completion"),
                                     ("mode", "strict profile requires required fixture mode"),
                                     ("group", "missing required group"),
                                     ("status", "command failed"),
                                     ("missing-harness", "missing/extra required harness"),
                                     ("stream-order", "capture must merge stderr"),
                                     ("backend-missing", "strict engine/backend environment"),
                                     ("backend-invalid", "strict engine/backend environment")):
            mutated = copy.deepcopy(cells)
            cell = mutated[1]
            record = cell["runs"][EVIDENCE.PACKAGES[1]]
            if mutation == "ancillary-zero":
                record["stdout"] += "running 0 tests\n" + summary(0)
            elif mutation in ("parent", "child", "group"):
                marker, value = {"parent": ("A1_TEST_COMPLETE", EVIDENCE.LOCK_PARENT),
                                 "child": ("A1_LOCK_CHILD_COMPLETE", EVIDENCE.LOCK_ROLES[-1]),
                                 "group": ("A1_GROUP_COMPLETE", "linux.tmpfs_names")}[mutation]
                record["stdout"] = EVIDENCE.remove_marker(record["stdout"], marker, value)
            elif mutation == "mode":
                record["stdout"] = record["stdout"].replace("mode=required", "mode=optional")
            elif mutation == "status":
                record["status"] = 73
            elif mutation == "missing-harness":
                del cell["runs"][EVIDENCE.PACKAGES[0]]
                self.reject(mutated, diagnostic)
                continue
            elif mutation == "stream-order":
                record["merged"] = False
            elif mutation == "backend-missing":
                del record["env"]["RATARMOUNT_TEST_SQLITE_BACKEND"]
            else:
                record["env"]["RATARMOUNT_TEST_SQLITE_BACKEND"] = "invalid"
            reseal_cell(cell)
            self.reject(mutated, diagnostic)

    def test_regression_target_cell_reuse_and_ordinary_strict_env_inheritance(self):
        cells = self.baseline()
        self.reject(cells[:1], "missing required engine/platform/deployment cell")
        mutated = copy.deepcopy(cells)
        mutated[1]["target_dir"] = mutated[0]["target_dir"]
        self.reject(mutated, "shared canonical engine target")
        for name in EVIDENCE.environment_cases(cells[0], cells[0]["environment_child_path"]):
            mutated = copy.deepcopy(cells)
            del mutated[0]["environment_controls"][name]
            self.reject(mutated, "missing parent/child ordinary/strict environment control")
        mutated = copy.deepcopy(cells)
        mutated[0]["environment_controls"]["ordinary"]["env"]["RATARMOUNT_TEST_SQLITE_BACKEND"] = "stock"
        self.reject(mutated, "environment control did not exercise requested branch")
        mutated = copy.deepcopy(cells)
        mutated[1]["environment_controls"]["child-missing"]["stdout"] = "running 0 tests\n" + summary(0)
        reseal(mutated[1]["environment_controls"]["child-missing"])
        self.reject(mutated, "strict environment negative failed for unrelated cause")

    def test_regression_source_lock_target_profile_and_stale_event_bindings(self):
        cells = self.baseline()
        for mutation, diagnostic in (("source-hash", "artifact replaced after enumeration"),
                                     ("lock-hash", "artifact replaced after enumeration"),
                                     ("target-env", "target/build environment mismatch"),
                                     ("strict-flag", "strict engine/backend environment"),
                                     ("profile", "cell profile/manifest mismatch"),
                                     ("deployment", "cell profile/manifest mismatch"),
                                     ("native-target", "native cell target changed"),
                                     ("stale-json", "SQLCipher dependency feature"),
                                     ("stock-cipher-graph", "stock graph unexpectedly has cipher")):
            with self.subTest(mutation=mutation):
                mutated = copy.deepcopy(cells)
                cell = mutated[1]
                if mutation == "source-hash":
                    cell["artifacts"][EVIDENCE.PACKAGES[1]]["source_sha256"] = "0" * 64
                elif mutation == "lock-hash":
                    cell["artifacts"][EVIDENCE.PACKAGES[1]]["lock_sha256"] = "0" * 64
                elif mutation == "target-env":
                    cell["commands"]["build"]["env"]["CARGO_TARGET_DIR"] = cells[0]["target_dir"]
                elif mutation == "strict-flag":
                    del cell["runs"][EVIDENCE.PACKAGES[1]]["env"]["RRS_A1_STRICT_ENGINE"]
                elif mutation == "profile":
                    cell["profile"] = "local-linux-partial"
                elif mutation == "deployment":
                    cell["deployment"] = "unrequested-deployment"
                elif mutation == "native-target":
                    cell["native_target"] = "aarch64-unknown-linux-gnu"
                    mutated[0]["native_target"] = cell["native_target"]
                elif mutation == "stale-json":
                    cell["commands"]["build"]["stdout"] = cells[0]["commands"]["build"]["stdout"]
                    reseal(cell["commands"]["build"])
                else:
                    mutated[0]["commands"]["graph"]["stdout"] += 'libsqlite3-sys feature "sqlcipher"\n'
                    reseal(mutated[0]["commands"]["graph"])
                self.reject(mutated, diagnostic)
        mutated = copy.deepcopy(cells)
        mutated[1]["artifacts"][EVIDENCE.PACKAGES[1]]["path"] = "/foreign/same-name"
        self.runner.calls.clear()
        with self.assertRaisesRegex(EVIDENCE.EvidenceError, "artifact replaced after enumeration"):
            EVIDENCE.run_binary(mutated[1], EVIDENCE.PACKAGES[1], EVIDENCE.A1_RUN_ARGS, self.output, "foreign")
        self.assertEqual(self.runner.calls, [])

    def test_regression_build_failure_never_executes_old_or_foreign_artifact(self):
        for mutation, diagnostic in (("nonzero", "command failed"), ("unfinished", "build-finished"),
                                     ("missing-feature", "command/package/feature mismatch")):
            with self.subTest(mutation=mutation):
                def mutate(name, record):
                    if name == "build":
                        if mutation == "nonzero":
                            record["status"] = 101
                        elif mutation == "unfinished":
                            record["stdout"] = record["stdout"].rsplit('\n', 2)[0] + '\n'
                        else:
                            record["argv"].remove("ratarmount-formats-sqlar/sqlcipher") if "--features" in record["argv"] else record["argv"].remove("ratarmount-formats-sqlar")
                self.runner.mutate = mutate
                self.runner.calls.clear()
                with self.assertRaisesRegex(EVIDENCE.EvidenceError, diagnostic):
                    EVIDENCE.build_cell(self.directory / mutation, "sqlcipher")
                self.assertTrue(all(command[0] in ("flock", "rustc") for command, _ in self.runner.calls))


    def test_regression_cli_rejects_missing_graph_before_any_binary_execution(self):
        cells = self.baseline()
        del cells[1]["commands"]["graph"]
        EVIDENCE.save_json(self.output / "sqlcipher/cell.json", cells[1])
        self.runner.calls.clear()
        with contextlib.redirect_stderr(io.StringIO()) as stderr:
            self.assertEqual(EVIDENCE.main(["run-engines", "--output-dir", str(self.output)]), 1)
        self.assertIn("extra/missing Cargo invocation", stderr.getvalue())
        self.assertEqual(self.runner.calls, [])

    def test_regression_runtime_failure_in_one_engine_propagates_through_cli(self):
        EVIDENCE.build_engines(self.output)
        def mutate(name, record):
            if name == EVIDENCE.PACKAGES[1] + "-A1" and record["env"]["RATARMOUNT_TEST_SQLITE_BACKEND"] == "sqlcipher":
                record["stdout"] = re.sub(r'"cipher_version": "4.6.1 community"', '"cipher_version": null', record["stdout"], count=1)
        self.runner.mutate = mutate
        with contextlib.redirect_stderr(io.StringIO()) as stderr:
            self.assertEqual(EVIDENCE.main(["run-engines", "--output-dir", str(self.output)]), 1)
        self.assertIn("runtime engine differs", stderr.getvalue())

    def test_regression_old_root_negative_uses_exact_verified_stock_index(self):
        cells = self.baseline()
        root = self.directory / "old-root"
        root.mkdir(mode=0o700)
        real_stat = Path.stat
        info = list(root.stat())
        info[4] = 0
        root_stat = os.stat_result(info)
        def simulated_root(path, *args, **kwargs):
            return root_stat if path == root else real_stat(path, *args, **kwargs)
        with mock.patch.object(Path, "stat", simulated_root):
            result = EVIDENCE.old_root_control(self.output, root)
            self.assertNotEqual(result["exit_code"], 0)
            command = self.runner.calls[-1][0]
            self.assertEqual(command[0], cells[0]["artifacts"][EVIDENCE.PACKAGES[1]]["path"])
            self.assertNotIn("cargo", command)
            def substitute(name, record):
                if name == "old-root-negative":
                    record.update(status=0, stdout="A1_TEST_COMPLETE substituted\n")
            self.runner.mutate = substitute
            with self.assertRaisesRegex(EVIDENCE.EvidenceError, "did not execute one test|substituted successful fixture"):
                EVIDENCE.old_root_control(self.output, root)


class StreamOrderingControls(unittest.TestCase):
    def test_regression_creation_time_merged_stderr_preserves_child_attribution(self):
        chunks = []
        for line in transcript("strict-linux").splitlines(keepends=True):
            offset = line.find("A1_")
            if offset >= 0:
                if offset:
                    chunks.append((1, line[:offset]))
                chunks.append((2, line[offset:]))
            else:
                chunks.append((1, line))
        # Inline subprocess source is accounted in this file; it creates no helper.
        program = "import os\nfor fd, text in " + repr(chunks) + ":\n os.write(fd, text.encode())\n"
        command = [sys.executable, "-c", program]
        with tempfile.TemporaryDirectory(prefix="a1-stream-") as directory:
            output = Path(directory)
            merged = EVIDENCE.capture(command, os.environ.copy(), output, "merged", merged=True)
            EVIDENCE.verify_record(merged, command, merged=True)
            self.assertEqual(merged["stdout"], transcript("strict-linux"))
            self.assertEqual(EVIDENCE.check(merged["stdout"], "strict-linux", merged["status"])["lock_children"], 6)
            split = EVIDENCE.capture(command, os.environ.copy(), output, "split", merged=False)
            with self.assertRaisesRegex(EVIDENCE.EvidenceError, "merge stderr at process creation"):
                EVIDENCE.verify_record(split, command, merged=True)
            for text in (split["stdout"], split["stdout"] + split["stderr"]):
                with self.assertRaisesRegex(EVIDENCE.EvidenceError, "nested harness outside lock parent"):
                    EVIDENCE.check(text, "strict-linux", 0)


if __name__ == "__main__":
    unittest.main()
