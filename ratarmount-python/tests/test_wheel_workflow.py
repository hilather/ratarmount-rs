"""Regression: wheel builds must exercise installed artifacts without publishing."""
from pathlib import Path

import pytest


def test_regression_wheel_matrix_tests_installed_artifacts_without_publishing():
    yaml = pytest.importorskip("yaml", reason="skip: PyYAML is optional")
    path = Path(__file__).resolve().parents[2] / ".github/workflows/python.yml"
    if not path.exists():
        pytest.skip("skip: workflow source is not shipped in a wheel/sdist")
    workflow = yaml.safe_load(path.read_text())
    jobs = workflow["jobs"]
    matrix = jobs["wheels"]["strategy"]["matrix"]["include"]
    assert {row["target"] for row in matrix} == {
        "x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu", "aarch64-apple-darwin",
    }
    assert all(row["manylinux"] == "2_28" for row in matrix if "linux" in row["target"])
    wheel_steps = jobs["wheels"]["steps"]
    mac_repair = next(step for step in wheel_steps if "delocate-wheel" in step.get("run", ""))
    assert mac_repair["if"] == "runner.os == 'macOS'"
    assert "--require-archs arm64" in mac_repair["run"]
    assert jobs["test"]["needs"] == "wheels"
    test_steps = jobs["test"]["steps"]
    assert any(step.get("uses") == "actions/download-artifact@v4" for step in test_steps)
    commands = "\n".join(step.get("run", "") for step in test_steps)
    assert "uv venv" in commands and "dist/*.whl" in commands
    assert "pytest ratarmount-python/tests" in commands
    assert "site-packages" in commands
    assert "torch" not in commands
    assert any(step.get("with", {}).get("command") == "sdist" for step in jobs["sdist"]["steps"])
    for job in jobs.values():
        for step in job["steps"]:
            assert "publish" not in step.get("uses", "").lower()
            assert "upload" not in step.get("with", {}).get("command", "")
