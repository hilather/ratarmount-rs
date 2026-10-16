"""Regression: Python publication must use the CLI's real Hub commit protocol."""
import base64
import hashlib
import http.server
import io
import json
import tarfile
import threading

import pytest

import ratarmount_rs as ratar
from test_process import _real_binary


@pytest.mark.parametrize("create_pr", [False, True])
def test_regression_real_cli_hf_publish_to_mock_server(tmp_path, monkeypatch, create_pr):
    monkeypatch.setenv("RATARMOUNT_BIN", _real_binary())
    archive_path = tmp_path / "a.tar"
    with tarfile.open(archive_path, "w") as tar:
        entry = tarfile.TarInfo("hello.txt")
        entry.size = 5
        tar.addfile(entry, io.BytesIO(b"hello"))
    objects = {"a.tar": archive_path.read_bytes()}
    requests = []
    operations = []
    committed = False

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_HEAD(self):
            self.respond()

        def do_GET(self):
            self.respond()

        def do_POST(self):
            self.respond()

        def respond(self):
            nonlocal committed
            requests.append((self.command, self.path, self.headers.get("Authorization")))
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            status = 200
            extra = {}
            if "/revision/" in self.path:
                sha = "b" * 40 if committed and (not create_pr or self.path.endswith("b" * 40)) else "a" * 40
                data = json.dumps({"sha": sha}).encode()
            elif "/refs" in self.path:
                data = json.dumps({"branches": [{"name": "main"}]}).encode()
            elif "/preupload/" in self.path:
                files = json.loads(body)["files"]
                data = json.dumps({"files": [{"path": f["path"], "uploadMode": "regular"} for f in files]}).encode()
            elif "/commit/" in self.path:
                ops = [json.loads(line) for line in body.splitlines()]
                operations.extend(ops)
                for op in ops:
                    if op["key"] == "file":
                        objects[op["value"]["path"]] = base64.b64decode(op["value"]["content"])
                committed = True
                response = {"commitOid": "b" * 40}
                if create_pr:
                    response["pullRequestUrl"] = "https://hub.example/datasets/org/data/discussions/1"
                data = json.dumps(response).encode()
            elif "/resolve/" in self.path:
                key = self.path.split("/resolve/", 1)[1].split("/", 1)[1]
                data = objects.get(key, b"")
                if key not in objects:
                    status = 404
                elif self.headers.get("Range"):
                    start, end = self.headers["Range"][6:].split("-", 1)
                    start = int(start)
                    end = min(int(end) if end else len(data) - 1, len(data) - 1)
                    extra["Content-Range"] = f"bytes {start}-{end}/{len(data)}"
                    data = data[start:end + 1]
                    status = 206
            else:
                data = b""
                status = 404
            self.send_response(status)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Accept-Ranges", "bytes")
            for key, value in extra.items():
                self.send_header(key, value)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(data)

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    monkeypatch.setenv("HF_ENDPOINT", f"http://127.0.0.1:{server.server_port}")
    monkeypatch.setenv("HF_TOKEN", "secret-hf-token")
    monkeypatch.setenv("HF_HUB_OFFLINE", "0")
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    monkeypatch.setenv("RATARMOUNT_HF_TREE_CACHE", str(tmp_path / "tree-cache"))
    try:
        with ratar.open(archive_path) as archive:
            result = archive.index.publish("hf://datasets/org/data/a.tar", revision="main", create_pr=create_pr)
        pointer = json.loads(objects["a.tar.index.ptr"])
        assert result.index_id == pointer["index_id"]
        assert hashlib.sha256(objects[f"a.tar.index.{result.index_id}.sqlite"]).hexdigest() == result.index_id
        assert result.commit == "b" * 40
        assert f"/resolve/{result.commit}/a.tar.index.ptr" in result.pointer_url
        assert bool(result.pull_request_url) is create_pr
        assert [op["key"] for op in operations] == ["header", "file", "file"]
        assert operations[0]["value"]["parentCommit"] == "a" * 40
        assert operations[1]["value"]["path"].endswith(".sqlite")
        assert operations[2]["value"]["path"] == "a.tar.index.ptr"
        assert all(auth == "Bearer secret-hf-token" for _, _, auth in requests)
        assert any("?create_pr=1" in path for _, path, _ in requests) is create_pr
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
