# securerepo:ignore-file - uses throwaway session tokens for the local test server.
import json
import threading
import urllib.error
import urllib.request

import pytest

from secure_repo.core.scanner import ScanOptions
from secure_repo.gui.server import AppState, QuietServer, make_handler


@pytest.fixture()
def server(tmp_path):
    state = AppState(ScanOptions(output_dir=str(tmp_path / "reports"), offline=True), "unit-test-token")
    srv = QuietServer(("127.0.0.1", 0), make_handler(state))
    state.port = srv.server_address[1]
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield state
    srv.shutdown()
    srv.server_close()


def call(state, path, body=None, token="unit-test-token", host=None):
    request = urllib.request.Request(f"http://127.0.0.1:{state.port}{path}",
                                     data=json.dumps(body).encode() if body is not None else None,
                                     method="POST" if body is not None else "GET")
    if token:
        request.add_header("X-SR-Token", token)
    if host:
        request.add_header("Host", host)
    if body is not None:
        request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, dict(response.headers), response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read()


def test_index_is_served_with_csp(server):
    status, headers, body = call(server, "/", token=None)
    assert status == 200
    assert "default-src 'self'" in headers["Content-Security-Policy"]
    assert b"SECURE" in body


def test_api_requires_token(server):
    assert call(server, "/api/context", token=None)[0] == 401
    assert call(server, "/api/context", token="wrong")[0] == 401
    assert call(server, "/api/context")[0] == 200


def test_dns_rebinding_host_is_rejected(server):
    assert call(server, "/api/context", host="attacker.example:80")[0] == 421


def test_scan_requires_authorization_confirmation(server, vulnerable_repo):
    status, _h, body = call(server, "/api/scan", {"kind": "local", "location": vulnerable_repo})
    assert status == 400 and b"authorized" in body


def test_static_path_traversal_is_blocked(server):
    assert call(server, "/static/..%2F..%2Fserver.py", token=None)[0] == 404
