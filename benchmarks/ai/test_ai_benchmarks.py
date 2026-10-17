"""Regression tests for benchmark validity, reporting and cleanup; stdlib only.

AI_TEST_FUSE=1 enables the real small FUSE smoke test outside the worker sandbox.
AI_TEST_NFS=1 enables the privileged kernel NFS loopback smoke test.
"""
import csv
from contextlib import nullcontext
import importlib.util
import json
import os
import signal
import select
import socket
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import tarfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

import common
from two_box_nfs import nfs_options


def load_script(filename):
    spec = importlib.util.spec_from_file_location(filename.replace("-", "_"), common.HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class BenchmarkRegressionTests(unittest.TestCase):
    """Regression: failed/short reads and unavailable tools must not become results."""

    def test_regression_short_duplicate_and_corrupt_samples_fail(self):
        expected = common.tally([b"a", b"b"])
        for payload in [[b"a"], [b"a", b"a"], [b"a", b"c"]]:
            with self.assertRaises(RuntimeError):
                common.check_tally(common.tally(payload), expected)
        common.check_tally(common.tally([b"b", b"a"]), expected)

    def test_regression_thread_partitions_never_drop_samples(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "source"
            expected = common.fixture(source, 3, 27)
            script = load_script("samples.py")
            self.assertEqual(script.read_files(sorted(source.iterdir()), 8), expected)

    def test_regression_library_loader_reuses_shard_indexes(self):
        script = load_script("samples.py")
        paths, calls = ["one", "two", "three"], []
        def reader(shards, *, worker_id, num_workers, archive_options):
            self.assertEqual(archive_options, {"index": "sidecar"})
            calls.append(worker_id)
            for shard in shards[worker_id::num_workers]:
                yield {"__key__": shard, "__url__": shard, "bin": shard.encode()}
        actual = script.read_library_threads(paths, 2, reader)
        self.assertEqual(actual, common.tally(path.encode() for path in paths))
        self.assertEqual(sorted(calls), [0, 1])

    def test_regression_csv_appends_one_header_and_quotes_notes(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "out.csv"
            args = common.parser("test").parse_args(["--output", str(output)])
            with patch("common.binary", side_effect=common.Skip("no binary")):
                first = common.Results("test", args)
                first.emit("one", note="a,b\nquoted")
                second = common.Results("test", args)
                second.emit("two", "skip", note="no fuse")
            with output.open() as stream:
                rows = list(csv.DictReader(stream))
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0]["note"], "a,b\nquoted")
            self.assertEqual(rows[1]["status"], "skip")
            self.assertNotEqual(rows[0]["run_id"], rows[1]["run_id"])

    def test_regression_schema_mismatch_refuses_mixed_csv(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "out.csv"
            output.write_text("wrong,header\n")
            args = common.parser("test").parse_args(["--output", str(output)])
            with patch("common.binary", side_effect=common.Skip("no binary")):
                result = common.Results("test", args)
                with self.assertRaisesRegex(ValueError, "schema mismatch"):
                    result.emit("bad")
            self.assertEqual(output.read_text(), "wrong,header\n")

    def test_regression_csv_parallel_writers_keep_rows(self):
        with tempfile.TemporaryDirectory() as temp:
            args = common.parser("test").parse_args(["--output", str(Path(temp) / "out.csv")])
            with patch("common.binary", side_effect=common.Skip("no binary")):
                r = common.Results("test", args)
            common.parallel(lambda i: r.emit(str(i), note="comma, newline\n"), range(32), 8)
            with args.output.open() as stream:
                rows = list(csv.DictReader(stream))
            self.assertEqual({row["case"] for row in rows}, {str(i) for i in range(32)})

    def test_regression_missing_tool_and_command_failure_are_distinct(self):
        with tempfile.TemporaryDirectory() as temp:
            args = common.parser("test").parse_args(["--output", str(Path(temp) / "out.csv")])
            with patch("common.binary", side_effect=common.Skip("no binary")):
                r = common.Results("test", args)
            r.case("missing", lambda: common.require("nonexistent-ai-benchmark-program"))
            r.case("failed", lambda: common.command([sys.executable, "-c", "raise SystemExit(9)"]))
            self.assertEqual([row["status"] for row in r.rows], ["skip", "error"])

    def test_regression_missing_fuse_skips_before_mount(self):
        with patch("common.sys.platform", "linux"), patch("common.os.access", return_value=False):
            with self.assertRaisesRegex(common.Skip, "/dev/fuse"):
                common.fuse_available()

    def test_regression_fuse_t_support_directory_is_detected_on_macos(self):
        with patch("common.sys.platform", "darwin"), patch("common.require"), \
             patch("common.Path.exists", autospec=True, side_effect=lambda path: str(path) == "/Library/Application Support/fuse-t"):
            common.fuse_available()
        with patch("common.sys.platform", "darwin"), patch("common.Path.exists", return_value=False):
            with self.assertRaisesRegex(common.Skip, "not detected"):
                common.fuse_available()

    def test_regression_nonpositive_worker_counts_rejected(self):
        for value in ["0", "-8"]:
            with self.assertRaises(Exception):
                common.positive(value)
        self.assertEqual(common.positive("8"), 8)

    def test_regression_rss_reads_vmrss_not_virtual_size(self):
        with tempfile.TemporaryDirectory() as temp:
            proc = Path(temp)
            (proc / "42").mkdir()
            (proc / "42/status").write_text("VmSize:\t999999 kB\nVmRSS:\t1234 kB\n")
            self.assertEqual(common.rss_kib(42, proc), 1234)
            (proc / "42/status").write_text("Name:\texited\n")
            with self.assertRaises(RuntimeError):
                common.rss_kib(42, proc)

    def test_regression_tensor_load_reads_payload_not_just_header(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "model.safetensors"
            header = json.dumps({"x": {"dtype": "U8", "shape": [4], "data_offsets": [0, 4]}}).encode()
            path.write_bytes(struct.pack("<Q", len(header)) + header + b"1234")
            size, digest = common.tensor_bytes(path)
            self.assertEqual(size, 4)
            path.write_bytes(struct.pack("<Q", len(header)) + header + b"1235")
            self.assertNotEqual(common.tensor_bytes(path)[1], digest)
            path.write_bytes(struct.pack("<Q", len(header)) + header + b"1")
            with self.assertRaisesRegex(ValueError, "offsets"):
                common.tensor_bytes(path)

    def test_regression_tensor_header_length_bounded(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "model.safetensors"
            path.write_bytes(struct.pack("<Q", 2**63))
            with self.assertRaisesRegex(ValueError, "oversized"):
                common.tensor_bytes(path)

    def test_regression_tensor_overlapping_ranges_fail(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "model.safetensors"
            header = json.dumps({"a": {"data_offsets": [0, 3]}, "b": {"data_offsets": [2, 4]}}).encode()
            path.write_bytes(struct.pack("<Q", len(header)) + header + b"1234")
            with self.assertRaisesRegex(ValueError, "offsets"):
                common.tensor_bytes(path)

    def test_regression_published_index_folder_names_include_archive_path(self):
        script = load_script("cold-index.py")
        self.assertEqual(script.index_name(Path("/tmp/shard.tar")), "_tmp_shard.tar.index.sqlite")
        self.assertNotEqual(script.index_name(Path("/a/shard.tar")), script.index_name(Path("/b/shard.tar")))

    def test_regression_nfs_v3_uses_mountport_v4_does_not(self):
        self.assertIn("mountport=20490", nfs_options("3", 20490))
        self.assertIn("vers=4.1", nfs_options("4", 20490))
        self.assertNotIn("mountport", nfs_options("4", 20490))

    def test_regression_nfs_server_interrupt_is_normal_shutdown(self):
        module = load_script("two_box_nfs.py")
        process = Mock()
        process.wait.side_effect = KeyboardInterrupt
        process.poll.return_value = -2
        recorder = Mock()
        recorder.args = type("Args", (), dict(mode="serve", source=Path("/fixture.tar"),
                                              bind="127.0.0.1", port=20490, version="4"))()
        with patch.object(module, "server", return_value=nullcontext(process)):
            module.run(recorder, Path("/unused"))
        recorder.emit.assert_called_once_with("serve", note="server stopped")

    def test_regression_failed_attempt_aborts_barrier_and_cleans_created(self):
        module = load_script("sandbox-attempts.py")
        class Recorder:
            args = type("Args", (), dict(attempts=4, runs=1))()
        cleaned, created = [], []
        def create(i):
            if i == 2:
                raise ValueError("injected setup failure")
            created.append(i)
            return i
        with self.assertRaises(Exception):
            module.attempts(Recorder(), "test", create, cleaned.append)
        self.assertEqual(sorted(cleaned), sorted(created))
        self.assertNotIn(2, cleaned)

    def test_regression_docker_attempts_use_resolved_image(self):
        module = load_script("sandbox-attempts.py")
        recorder = Mock()
        recorder.args = type("Args", (), dict(attempts=1, runs=1, docker_image="alpine:3.20"))()
        recorder.case.side_effect = lambda name, action: action() if name == "docker-cp" else None
        def docker(argv, **_):
            if argv[1:3] == ["image", "inspect"]:
                return "sha256:fixed"
            if argv[1] == "create":
                self.assertEqual(argv[4], "sha256:fixed")
                return "container-id"
            return ""
        with patch.object(module, "require"), patch.object(module, "repo", return_value=Path("/fixture")), \
             patch.object(module, "command", side_effect=docker):
            module.run(recorder, Path("/unused"))
        self.assertIn("image=sha256:fixed", recorder.emit.call_args.kwargs["note"])

    def test_regression_timed_out_docker_create_cleans_known_name(self):
        module = load_script("sandbox-attempts.py")
        recorder = Mock()
        recorder.run_id = "unit"
        recorder.args = type("Args", (), dict(attempts=1, runs=1, docker_image="alpine:3.20"))()
        recorder.case.side_effect = lambda name, action: action() if name == "docker-cp" else None
        removed = []
        def docker(argv, **_):
            if argv[1:3] == ["image", "inspect"]:
                return "sha256:fixed"
            if argv[1] == "create":
                raise subprocess.TimeoutExpired(argv, 300)
            if argv[1] == "rm":
                removed.append(argv[-1])
            return ""
        with patch.object(module, "require"), patch.object(module, "repo", return_value=Path("/fixture")), \
             patch.object(module, "command", side_effect=docker):
            with self.assertRaises(subprocess.TimeoutExpired):
                module.run(recorder, Path("/unused"))
        self.assertEqual(removed, ["ai-bench-unit-0"])

    def test_regression_failed_cleanup_never_deletes_live_mount(self):
        with tempfile.TemporaryDirectory() as temp:
            args = common.parser("test").parse_args(["--output", str(Path(temp) / "out.csv")])
            def action(_, work):
                (work / "live-mount").mkdir()
                raise RuntimeError("injected cleanup failure")
            try:
                with patch("common.HERE", Path(temp)), patch("common.binary", side_effect=common.Skip("no binary")), \
                     patch("common.os.path.ismount", side_effect=lambda path: Path(path).name == "live-mount"):
                    self.assertEqual(common.main("test", args, action), 1)
                self.assertEqual(len(list((Path(temp) / ".cache").glob("*/live-mount"))), 1)
            finally:
                common.ACTIVE_MOUNTS.clear()

    def test_regression_cached_repo_wrong_commit_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            (Path(temp) / ".cache/zlib").mkdir(parents=True)
            with patch("common.HERE", Path(temp)), patch("common.require"), \
                 patch("common.command", return_value="wrong-commit"):
                with self.assertRaisesRegex(RuntimeError, "wrong commit"):
                    common.repo()

    def test_regression_dirty_cached_repo_cannot_bias_comparison(self):
        with tempfile.TemporaryDirectory() as temp:
            (Path(temp) / ".cache/zlib").mkdir(parents=True)
            with patch("common.HERE", Path(temp)), patch("common.require"), \
                 patch("common.command", side_effect=[common.REPO_COMMIT, " M zlib.h"]):
                with self.assertRaisesRegex(RuntimeError, "dirty"):
                    common.repo()

    def test_regression_mount_failure_closes_process_and_log(self):
        with tempfile.TemporaryDirectory() as temp:
            mount = common.Mount([sys.executable, "-c", "raise SystemExit(1)"], Path(temp) / "mnt")
            with self.assertRaisesRegex(RuntimeError, "mount failed"):
                mount.__enter__()
            self.assertIsNotNone(mount.process.poll())
            self.assertTrue(mount.log.closed)

    def test_regression_unmount_failure_still_stops_child(self):
        with tempfile.TemporaryDirectory() as temp:
            mount = common.Mount([], Path(temp) / "mnt")
            mount.process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(90)"])
            mount.log = (Path(temp) / "log").open("w")
            with patch("common.unmount", side_effect=RuntimeError("busy")):
                with self.assertRaisesRegex(RuntimeError, "busy"):
                    mount.__exit__(None, None, None)
            self.assertIsNotNone(mount.process.poll())
            self.assertTrue(mount.log.closed)

    def test_regression_long_checkout_keeps_sandbox_inspection_socket_short(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            work = root / ("long-checkout-" * 12)
            work.mkdir()
            factory = Mock()
            process = Mock()
            process.poll.return_value = None
            def spawn(argv, **_):
                Path(argv[argv.index("--socket") + 1]).touch()
                return process
            with patch("common.sys.platform", "linux"), patch("common.fuse_available"), patch("common.binary", return_value="ratarmount"), \
                 patch("common.subprocess.Popen", side_effect=spawn), \
                 patch.dict(sys.modules, {"ratarmount_sandbox": SimpleNamespace(RatarmountSandbox=factory)}):
                with common.sandbox(work, Path("/repo"), root):
                    sock = factory.call_args.args[0]
                    state = sock.parent
                    inspection = state / "attempts" / "attempt-123456" / "inspect.sock"
                    self.assertLess(len(os.fsencode(inspection)), 108)
                    self.assertTrue(sock.exists())
                self.assertFalse(state.exists())
                with self.assertRaisesRegex(common.Skip, "socket path too long"):
                    with common.sandbox(work, Path("/repo"), work):
                        self.fail("long state root accepted")
                self.assertEqual(list(work.glob(".s*")), [])

    def test_regression_scripts_have_runnable_help(self):
        scripts = ["samples.py", "sandbox-attempts.py", "build-test.py", "cold-index.py",
                   "mount-memory.py", "model-load.py", "hf-dataset.py", "two_box_nfs.py"]
        for script in scripts:
            output = common.command([sys.executable, common.HERE / script, "--help"])
            self.assertIn("--output", output)

    @unittest.skipUnless(os.getenv("AI_TEST_FUSE") == "1", "skip: set AI_TEST_FUSE=1 with /dev/fuse")
    def test_regression_real_fuse_samples_and_cleanup(self):
        common.fuse_available()
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "results.csv"
            common.command([sys.executable, common.HERE / "samples.py", "--samples", "16",
                            "--sample-bytes", "1024", "--shard-size", "4K", "--output", output])
            with output.open() as stream:
                rows = list(csv.DictReader(stream))
            self.assertTrue(any(row["case"] == "fuse" and row["status"] == "ok" for row in rows))
            self.assertFalse(any(row["status"] == "error" for row in rows))

    @unittest.skipUnless(os.getenv("AI_TEST_FUSE") == "1", "skip: set AI_TEST_FUSE=1 with /dev/fuse")
    def test_regression_real_sandbox_index_and_rss_cases(self):
        common.fuse_available()
        cases = [
            ("sandbox-attempts.py", ["--attempts", "4"], {"ratarmount-sandbox"}),
            ("build-test.py", ["--jobs", "2"], {"sandbox"}),
            ("cold-index.py", ["--gib", "0.001953125", "--shard-size", "1M"], {"mount-scan", "mount-published"}),
            ("mount-memory.py", ["--mounts", "2", "--samples", "8"], {"ratarmount"}),
        ]
        with tempfile.TemporaryDirectory() as temp:
            for script, argv, required in cases:
                output = Path(temp) / (script + ".csv")
                common.command([sys.executable, common.HERE / script, *argv, "--output", output], timeout=600)
                with output.open() as stream:
                    rows = list(csv.DictReader(stream))
                successful = {row["case"] for row in rows if row["status"] == "ok"}
                self.assertTrue(required <= successful, f"missing cases for {script}: {required - successful}")
                self.assertFalse(any(row["status"] == "error" for row in rows))

    @unittest.skipUnless(os.getenv("AI_TEST_SERVER") == "1", "skip: set AI_TEST_SERVER=1 with a built ratarmount binary")
    def test_regression_real_nfs_server_interrupt_closes_listener(self):
        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp)
            member = work / "payload.bin"
            member.write_bytes(b"NFS smoke fixture")
            archive = work / "fixture.tar"
            with tarfile.open(archive, "w") as tar:
                tar.add(member, arcname=member.name)
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0))
                port = probe.getsockname()[1]
            output = work / "results.csv"
            process = subprocess.Popen([sys.executable, common.HERE / "two_box_nfs.py", "serve",
                "--source", archive, "--version", "3", "--port", str(port), "--output", output],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
            try:
                ready, _, _ = select.select([process.stdout], [], [], 30)
                self.assertTrue(ready, "NFS helper did not report readiness")
                line = process.stdout.readline()
                self.assertTrue(line.startswith("Serving "), line)
                with socket.create_connection(("127.0.0.1", port), timeout=1):
                    pass
                process.send_signal(signal.SIGINT)
                stdout, stderr = process.communicate(timeout=30)
                self.assertEqual(process.returncode, 0, stdout + stderr)
                with output.open() as stream:
                    rows = list(csv.DictReader(stream))
                self.assertTrue(any(row["case"] == "serve" and row["status"] == "ok" for row in rows))
                with self.assertRaises(OSError):
                    socket.create_connection(("127.0.0.1", port), timeout=1)
            finally:
                # Restrict emergency cleanup to this test's own process group.
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                process.communicate(timeout=10)

    @unittest.skipUnless(os.getenv("AI_TEST_NFS") == "1", "skip: set AI_TEST_NFS=1 with CAP_SYS_ADMIN and mount.nfs")
    def test_regression_real_nfs_loopback_matches_native_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "results.csv"
            common.command([sys.executable, common.HERE / "two_box_nfs.py", "loopback", "--mib", "1", "--output", output])
            with output.open() as stream:
                rows = list(csv.DictReader(stream))
            self.assertTrue(any(row["case"] == "nfs-read" and row["status"] == "ok" for row in rows))


if __name__ == "__main__":
    unittest.main()
