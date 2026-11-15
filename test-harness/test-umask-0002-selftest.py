#!/usr/bin/env python3
"""Regression tests for the umask runner; no Rust build or FUSE required."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


RUNNER = Path(__file__).with_name("test-umask-0002.sh")
FAKE_CARGO = r'''#!/usr/bin/env python3
import json
import os
from pathlib import Path
import subprocess
import sys

calls = Path(os.environ["UMASK_TEST_CALLS"])
with calls.open("a") as log:
    log.write(json.dumps({
        "args": sys.argv[1:],
        "umask": subprocess.check_output(["bash", "-c", "umask"], text=True).strip(),
    }) + "\n")
number = len(calls.read_text().splitlines())
case = os.environ["UMASK_TEST_CASE"]
if number == 3:
    if case == "zero":
        print("test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 25 filtered out;")
        sys.exit(0)
    if case == "ignored":
        print("test result: ok. 0 passed; 0 failed; 25 ignored; 0 measured; 0 filtered out;")
        sys.exit(0)
    if case == "build":
        print("Finished test profile; no tests executed")
        sys.exit(0)
    if case == "list":
        print("regression_example: test\n\n1 test, 0 benchmarks")
        sys.exit(0)
print("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;")
if number == 3 and case == "failure":
    print("cargo command failed after a successful child test", file=sys.stderr)
    sys.exit(17)
'''


class UmaskRunnerTests(unittest.TestCase):
    def run_case(self, case, *args):
        with tempfile.TemporaryDirectory(prefix="umask-selftest-") as tmp:
            root = Path(tmp)
            cargo = root / "fake-cargo"
            cargo.write_text(FAKE_CARGO)
            cargo.chmod(0o700)
            calls = root / "calls.jsonl"
            result = subprocess.run(
                ["bash", str(RUNNER), *args],
                env={
                    **os.environ,
                    "CARGO": str(cargo),
                    "TMPDIR": str(root),
                    "UMASK_TEST_CASE": case,
                    "UMASK_TEST_CALLS": str(calls),
                },
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            self.assertTrue(calls.exists(), result.stderr)
            records = [json.loads(line) for line in calls.read_text().splitlines()]
            self.assertEqual(len(records), 8, result.stdout + result.stderr)
            self.assertTrue(all(row["umask"] == "0002" for row in records))
            self.assertTrue(all(row["args"][0] == "test" for row in records))
            self.assertFalse(list(root.glob("ratarmount-umask.*")), "log leaked")
            return result, records

    def test_regression_success_runs_every_suite_and_preserves_arguments(self):
        """Regression: extra arguments reach every run without word splitting."""
        args = ("--release", "--", "--skip", "a test name")
        result, records = self.run_case("success", *args)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(all(row["args"][-len(args):] == list(args) for row in records))

    def test_regression_cargo_failure_is_not_hidden_by_tee_or_later_success(self):
        result, _ = self.run_case("failure")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("failed under umask 0002", result.stderr)

    def test_regression_zero_selected_tests_fail(self):
        result, _ = self.run_case("zero", "--", "--skip", "")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("reported no passed tests", result.stderr)

    def test_regression_only_ignored_tests_fail(self):
        result, _ = self.run_case("ignored")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("reported no passed tests", result.stderr)

    def test_regression_build_only_is_not_a_test_pass(self):
        result, _ = self.run_case("build", "--no-run")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("reported no passed tests", result.stderr)

    def test_regression_list_only_is_not_a_test_pass(self):
        result, _ = self.run_case("list", "--", "--list")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("reported no passed tests", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
