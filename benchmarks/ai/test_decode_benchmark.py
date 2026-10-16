"""Regression checks for benchmark accounting; no external tools or FUSE needed."""
import importlib.util
from pathlib import Path
import unittest
import sys

sys.dont_write_bytecode = True

spec = importlib.util.spec_from_file_location("benchmark", Path(__file__).with_name("decode-benchmark.py"))
benchmark = importlib.util.module_from_spec(spec)
spec.loader.exec_module(benchmark)


class BenchmarkRegression(unittest.TestCase):
    def test_decode_path_reports_serial_and_prefetched_readers(self):
        stats = benchmark.summary("INFO zstd-read-summary bytes=128 prefetched=0 synchronous=1", "zstd-read-summary")
        self.assertEqual(benchmark.decode_fields(stats)["decode_path"], "synchronous")
        stats = benchmark.summary("""index unrelated=99
INFO zstd-read-summary prefetched=4 ready=3 waited=1 wait_ns=1200000
INFO zstd-read-summary prefetched=2 ready=2 waited=0 wait_ns=0
""", "zstd-read-summary")
        self.assertEqual(benchmark.decode_fields(stats), dict(
            decode_path="decode-ahead", frames_prefetched=6, frames_ready=5,
            frames_waited=1, synchronous_frames=0, decode_wait_ms=1.2))

    def test_request_limit_is_maximum_not_sum(self):
        stats = benchmark.summary("""fuse-read-summary requests=1 max_request=131072 service_ns=150
fuse-read-summary requests=2 max_request=1048576 service_ns=250""", "fuse-read-summary")
        self.assertEqual(stats, dict(requests=3, max_request=1048576, service_ns=400))

    def test_fuse_matrix_includes_cached_and_direct_serial_and_parallel(self):
        cases = benchmark.fuse_cases(4)
        self.assertEqual(len(cases), 8)
        for direct in [0, 1]:
            for caller in ["cat", "dd"]:
                for threads in [1, 4]:
                    self.assertIn((direct, caller, threads), cases)
        self.assertEqual(len(benchmark.fuse_cases(1)), 4)

    def test_missing_or_short_read_is_not_reported_as_full_throughput(self):
        benchmark.require_bytes({"bytes": 256}, 256)
        for stats in [{}, {"bytes": 128}]:
            with self.assertRaises(RuntimeError):
                benchmark.require_bytes(stats, 256)

    def test_session_decimal_values_survive_summary(self):
        stats = benchmark.summary("session-read-summary bytes=268435456 seconds=0.123456 MB_per_s=2174.3 CPU_percent=350.1", "session-read-summary")
        self.assertEqual(stats["bytes"], 268435456)
        self.assertEqual(stats["seconds"], 0.123456)
        self.assertEqual(stats["CPU_percent"], 350.1)


if __name__ == "__main__":
    unittest.main()
