#!/usr/bin/env python3
"""Regression: native coverage preserves production membership and diagnostics."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("internal_read_native", HERE / "native.py")
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)


class NativeContract(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.source = str(Path(self.directory.name) / "src/lib.rs")
        self.settings = {"targets": [{"source": self.source, "crate": "example",
                                      "crate_types": ["lib"]}]}
        self.arguments = ["clippy-driver", "rustc", self.source,
                          "--crate-name", "example", "--crate-type", "lib"]

    def test_regression_all_targets_does_not_impose_inventory_on_tests(self):
        for extra in ([], ["--test"]):
            command, env, selected = native.compiler_command(self.arguments + extra, self.settings)
            self.assertEqual(selected, not extra)
            if selected:
                self.assertEqual(env["CLIPPY_CONF_DIR"], str(HERE))
                self.assertIn("internal_read_inventory", command)
                self.assertIn("unused_macros", command)
                for lint in ("warnings", "clippy::disallowed_methods", "unfulfilled_lint_expectations"):
                    self.assertEqual(command[command.index(lint) - 1], "-D")
                self.assertEqual(command[command.index("unused_macros") - 1], "-F")
            else:
                self.assertEqual(command[0], "rustc")
                self.assertNotIn("internal_read_inventory", command)

    def test_regression_same_source_with_wrong_crate_identity_is_not_production(self):
        arguments = ["different" if arg == "example" else arg for arg in self.arguments]
        command, _, selected = native.compiler_command(arguments, self.settings)
        self.assertFalse(selected)
        self.assertEqual(command[0], "rustc")

    def test_regression_selected_package_as_dependency_keeps_ordinary_rustc(self):
        command, _, selected = native.compiler_command(self.arguments[1:], self.settings)
        self.assertFalse(selected)
        self.assertEqual(command[0], "rustc")
        self.assertNotIn("internal_read_inventory", command)

    def test_regression_other_clippy_errors_cannot_satisfy_negative_control(self):
        output = '\n'.join(json.dumps({"reason": "compiler-message", "message": {
            "code": {"code": code}}}) for code in ("E0433", "unused_macros"))
        self.assertNotIn("clippy::disallowed_methods", native.diagnostics(output))
        output += '\n' + json.dumps({"reason": "compiler-message", "message": {
            "code": {"code": "clippy::disallowed_methods"}}})
        self.assertIn("clippy::disallowed_methods", native.diagnostics(output))

    def test_regression_each_feature_covers_no_default_and_keeps_native_target(self):
        command = native.hack_arguments("ratarmount-index", [], "-D")
        self.assertIn("--each-feature", command)
        self.assertEqual(command[command.index("warnings") - 1], "-D")
        self.assertEqual(command[command.index("clippy::disallowed_methods") - 1], "-D")
        self.assertIn("--all-targets", command)
        self.assertNotIn("--exclude-no-default-features", command)
        self.assertNotIn("--target", command)
        self.assertEqual(command[-4:], ["-D", "clippy::disallowed_macros", "-F", "unused_macros"])

    def test_regression_matrix_exclusions_remain_explicit(self):
        matrix = json.loads((HERE / "native.json").read_text())
        restricted = set(json.loads((HERE / "policy.json").read_text())["restricted_packages"])
        self.assertEqual(matrix["macos"]["packages"], "restricted_packages")
        self.assertEqual(set(matrix["windows"]["packages"]), {
            "ratarmount-index", "ratarmount-formats-tar", "ratarmount-formats-zip"})
        self.assertTrue(set(matrix["windows"]["packages"]) <= restricted)
        for row in (matrix["macos"], matrix["windows"]):
            self.assertTrue(row["reason"])

    def test_regression_excluded_feature_is_not_passed_to_unrelated_packages(self):
        metadata = {"packages": [{"name": "index", "features": {"test-hooks": []}},
                                 {"name": "compress", "features": {"gzip-rapidgzip-isal": []}}]}
        exclusions = ["gzip-rapidgzip-isal"]
        self.assertEqual(native.package_exclusions(metadata, "index", exclusions), [])
        self.assertEqual(native.package_exclusions(metadata, "compress", exclusions), exclusions)


if __name__ == "__main__":
    unittest.main()
