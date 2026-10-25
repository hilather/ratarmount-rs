#!/usr/bin/env python3
"""Regression: the existing check job keeps fmt first and runs compiler policy."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]


class CiContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        cls.jobs = cls.workflow.split("\njobs:\n", 1)[1]
        match = re.search(r"(?ms)^  check:\n(.*?)(?=^  [a-zA-Z0-9_-]+:|\Z)", cls.jobs)
        if match is None:
            raise AssertionError("existing check job is missing")
        cls.check = match.group(1)

    def test_regression_linux_policy_keeps_existing_job_and_budget(self):
        names = set(re.findall(r"(?m)^  ([a-zA-Z0-9_-]+):", self.jobs))
        self.assertEqual(names, {"check", "checked-open-aarch64", "nfsv4", "bittorrent", "benchmark-gates", "benchmark-gates-full", "fuse-harness", "macos", "windows-lib", "msrv"})
        self.assertIn("name: fmt + clippy + test", self.check)
        self.assertIn("timeout-minutes: 45", self.check)
        self.assertIn("RUSTFLAGS: -Dwarnings", self.workflow)

    def test_regression_fmt_precedes_every_compiler_policy_and_test_gate(self):
        fmt = self.check.index("cargo fmt --all -- --check")
        for command in ["compiler/build.py", "compiler/test_driver.py", "syntax/test_compiled.py", "syntax/Cargo.toml", "controls/run.py", "test_policy.py", "test_manifest.py", "test_diagnostics.py", "test_dispatch.py", "witnesses/test_provenance.py", "witnesses/run.py", "witnesses/test_journal_protocol.py", "policy.py", "cargo clippy --workspace --all-targets -- -D warnings", "cargo test --workspace"]:
            self.assertGreater(self.check.index(command), fmt, command)
        self.assertLess(self.check.index("compiler/build.py"), self.check.index("compiler/test_driver.py"))
        self.assertLess(self.check.index("test_dispatch.py"), self.check.index("Production Clippy and reviewed manifest diff"))

    def test_regression_pinned_policy_keeps_ordinary_workspace_gates(self):
        self.assertIn("uses: dtolnay/rust-toolchain@stable", self.check)
        self.assertIn("rustup toolchain install 1.98.0 --profile minimal --component clippy", self.check)
        self.assertIn('DRIVER="$HOME/.cargo/internal-read-clippy/target/debug/clippy-driver"', self.check)
        self.assertIn("CARGO_BUILD_JOBS=2 flock /tmp/muse-cargo.lock cargo clippy --workspace --all-targets -- -D warnings", self.check)
        self.assertIn("CARGO_BUILD_JOBS=2 flock /tmp/muse-cargo.lock cargo test --workspace", self.check)
        self.assertIn('RATARMOUNT_REQUIRE_XORRISO: "1"', self.check)
        self.assertIn("run: python3 -I packaging/internal-read-clippy/policy.py", self.check)
        self.assertNotIn("policy.py --collect", self.check)

    def test_regression_separate_policy_caches_and_retired_collector(self):
        self.assertIn("uses: Swatinem/rust-cache@v2", self.check)
        self.assertIn("target/internal-read-policy", self.check)
        self.assertIn("~/.cargo/internal-read-clippy", self.check)
        self.assertNotIn("test-internal-read-inventory.py", self.workflow)
        self.assertNotIn("inventory-baseline", self.workflow)
        self.assertNotIn("e6ca64e3a3d2c509840ca147fcf0d71703546318", self.workflow)

    def test_regression_retained_python_and_platform_checks(self):
        for command in ["packaging/test-windows-lib-ci.sh", "packaging/test-workspace-lock-version.sh", "packaging/test-portable-deps-selftest.sh", "test-harness/canonical-hash/reference.py --self-test", "packaging/audit_native_exports.py --self-test", "packaging/test-wheel-blake3-no-neon.sh", "test-harness/test-aarch64-checked-open-ci.sh", "packaging/test-systemd-unit.sh"]:
            self.assertIn(command, self.check)

    def test_regression_inventory_policy_is_linux_only(self):
        """Regression: #201 must not enable unapproved native-only operations."""
        self.assertIn("runs-on: ubuntu-latest", self.check)
        self.assertIn("native.py --fixtures", self.check)
        self.assertNotIn("internal-read-windows:", self.jobs)
        for job in ("macos", "windows-lib"):
            match = re.search(r"(?ms)^  " + job + r":\n(.*?)(?=^  [a-zA-Z0-9_-]+:|\Z)", self.jobs)
            self.assertIsNotNone(match, "pre-existing platform build must remain")
            body = match.group(1)
            self.assertNotIn("internal-read-clippy/", body)
            self.assertNotIn("cargo-hack", body)
            self.assertNotIn("internal-read-native", body)
        self.assertIn("name: macOS (build + test)", self.jobs)
        self.assertIn("name: windows-lib (core+index gate; session skippable)", self.jobs)


if __name__ == "__main__":
    unittest.main()
