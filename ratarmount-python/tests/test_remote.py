"""Regression: HTTP archive URLs reach Session without being treated as paths."""
import http.server
import threading
from urllib.parse import urlsplit

import pytest

import ratarmount_rs as ratar


@pytest.fixture
def archive_url(sample):
    path, payloads = sample
    payload = path.read_bytes()
    requests = []

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def do_HEAD(self):
            self.respond(False)

        def do_GET(self):
            self.respond(True)

        def respond(self, body):
            if urlsplit(self.path).path != "/sample.tar":
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            range_header = self.headers.get("Range")
            requests.append((self.command, range_header))
            start, end = 0, len(payload) - 1
            if range_header:
                begin, finish = range_header.removeprefix("bytes=").split("-", 1)
                start = int(begin)
                end = min(int(finish) if finish else end, end)
            if start >= len(payload):
                self.send_response(416)
                self.send_header("Content-Range", f"bytes */{len(payload)}")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self.send_response(206 if range_header else 200)
            self.send_header("Accept-Ranges", "bytes")
            self.send_header("Content-Length", str(end - start + 1))
            if range_header:
                self.send_header("Content-Range", f"bytes {start}-{end}/{len(payload)}")
            self.send_header("ETag", '"local-fixture-v1"')
            self.end_headers()
            if body:
                self.wfile.write(payload[start:end + 1])

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/sample.tar", payloads, requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_regression_http_url_open_and_read_release_gil(archive_url):
    # The HTTP server is another Python thread. It can answer Session requests
    # only while the native open/read detach from the interpreter.
    url, payloads, requests = archive_url
    with ratar.open(url) as archive:
        assert archive.stat("a/first.txt").size == len(payloads["a/first.txt"])
        assert archive.read("a/first.txt") == payloads["a/first.txt"]
        assert archive.read("z-last-name.bin", 5000, 100000) == payloads["z-last-name.bin"][5000:105000]
        with archive.open("a/second.txt") as member:
            assert member.read() == payloads["a/second.txt"]
        with pytest.raises(ratar.NotMappable):
            archive.mmap("a/first.txt")
    assert any(method == "GET" and header for method, header in requests)
