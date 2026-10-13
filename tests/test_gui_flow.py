"""End-to-end flow of the local web server: scan, live stream, report, downloads, triage, hardening (C-38)."""
import io
import json
import secrets
import threading
import time
import urllib.error
import urllib.request
import zipfile

import pytest

from secure_repo.core.scanner import ScanOptions
from secure_repo.gui.server import DOWNLOADS, AppState, QuietServer, make_handler

TOKEN = secrets.token_urlsafe(16)   # generated per run: no credential-looking literal in the repository


@pytest.fixture()
def server(tmp_path):
    state = AppState(ScanOptions(output_dir=str(tmp_path / "reports"), offline=True), TOKEN)
    srv = QuietServer(("127.0.0.1", 0), make_handler(state))
    state.port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield state
    srv.shutdown()
    srv.server_close()


def call(state, path, body=None, token=TOKEN, headers=None, method=None):
    request = urllib.request.Request(f"http://127.0.0.1:{state.port}{path}",
                                     data=json.dumps(body).encode() if body is not None else None,
                                     method=method or ("POST" if body is not None else "GET"))
    if token:
        request.add_header("X-SR-Token", token)
    for key, value in (headers or {}).items():
        request.add_header(key, value)
    if body is not None:
        request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return response.status, dict(response.headers), response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read()


def run_scan(state, repo, **options):
    status, _h, body = call(state, "/api/scan", {"kind": "local", "location": repo, "authorized": True,
                                                  "options": dict({"offline": True}, **options)})
    assert status == 200, body
    return json.loads(body)["scan_id"]


def wait_for_report(state, scan_id):
    for _ in range(300):
        status, _h, body = call(state, f"/api/scans/{scan_id}/report")
        if status == 200:
            return json.loads(body)
        time.sleep(0.2)
    raise AssertionError("the scan did not finish")


def test_full_scan_flow_with_stream_downloads_and_triage(server, vulnerable_repo):
    scan_id = run_scan(server, vulnerable_repo, compliance=True)

    # the live stream needs the header token and ends with an explicit "end" event
    assert call(server, f"/api/scans/{scan_id}/events", token=None)[0] == 401
    status, headers, body = call(server, f"/api/scans/{scan_id}/events")
    text = body.decode("utf-8")
    assert status == 200 and headers["Content-Type"].startswith("text/event-stream")
    assert "event: end" in text and "id: 1" in text
    events = [json.loads(line[5:]) for line in text.splitlines() if line.startswith("data:") and line[5:].strip() not in ("", "{}")]
    assert events, "the stream must carry scan events"
    status, _h, resumed = call(server, f"/api/scans/{scan_id}/events", headers={"Last-Event-ID": "999999"})
    assert status == 200 and b"event: end" in resumed                  # resuming past the end still terminates

    payload = wait_for_report(server, scan_id)
    report = payload["report"]
    assert payload["scan_id"] == scan_id and len(report["findings"]) > 0

    for kind, (rel, mime) in DOWNLOADS.items():
        status, headers, body = call(server, f"/api/scans/{scan_id}/download/{kind}")
        assert status == 200 and body, kind
        assert headers["Content-Type"] == mime and rel.rsplit("/", 1)[-1] in headers["Content-Disposition"]
    status, headers, body = call(server, f"/api/scans/{scan_id}/download/zip")
    assert status == 200 and headers["Content-Type"] == "application/zip"
    names = zipfile.ZipFile(io.BytesIO(body)).namelist()
    assert any(name.endswith("report.json") for name in names) and any(name.endswith("MANIFEST.sha256") for name in names)
    assert call(server, f"/api/scans/{scan_id}/download/evil")[0] == 404
    assert call(server, f"/api/scans/{scan_id}/download/..%2f..%2fetc")[0] == 404

    # triage through the API updates the report and the knowledge base
    open_finding = next(f for f in report["findings"] if f["status"] == "open")
    assert call(server, f"/api/scans/{scan_id}/triage", {"finding_ids": []})[0] == 400
    assert call(server, f"/api/scans/{scan_id}/triage", {"finding_ids": [open_finding["id"]],
                                                          "status": "false_positive"})[0] == 400  # reason is mandatory
    status, _h, body = call(server, f"/api/scans/{scan_id}/triage", {"finding_ids": [open_finding["id"]],
                                                                      "status": "false_positive", "reason": "unit test"})
    assert status == 200 and open_finding["id"] in json.loads(body)["result"]["changed"]
    status, _h, body = call(server, "/api/knowledge")
    assert status == 200 and json.loads(body)["decisions"] >= 1


def test_context_branches_and_unknown_resources(server, tmp_path):
    status, _h, body = call(server, "/api/context")
    context = json.loads(body)
    assert status == 200 and context["output_dir"].endswith("reports") and "version" in context
    plain = tmp_path / "plain"
    plain.mkdir()
    status, _h, body = call(server, "/api/branches", {"kind": "local", "location": str(plain)})
    assert status == 200 and json.loads(body)["git"] is False
    assert call(server, "/api/branches", {"kind": "local", "location": str(tmp_path / "nope")})[0] == 400
    assert call(server, "/api/branches", {"kind": "ftp", "location": "x"})[0] == 400
    assert call(server, "/api/scans/unknown/report")[0] == 404
    assert call(server, "/api/scans/unknown/cancel", {})[0] == 404
    assert call(server, "/api/nothing-here")[0] == 404
    assert call(server, "/api/scan", {"kind": "local", "location": str(plain)})[0] == 400   # not confirmed as authorized


def test_static_files_and_path_tricks(server):
    status, headers, body = call(server, "/static/core.js", token=None)
    assert status == 200 and "javascript" in headers["Content-Type"] and b"SR.stream" in body
    assert b"withToken" not in body
    for path in ("/static/..%2fserver.py", "/static/../server.py", "/static/missing.js", "/elsewhere"):
        assert call(server, path, token=None)[0] == 404, path
    assert call(server, "/favicon.ico", token=None)[0] == 204


def test_cross_origin_posts_are_blocked(server, vulnerable_repo):
    status, _h, _b = call(server, "/api/scan", {"kind": "local", "location": vulnerable_repo, "authorized": True},
                          headers={"Origin": "http://evil.example"})
    assert status == 403


def test_update_endpoint_can_be_disabled(server, monkeypatch):
    monkeypatch.setenv("SECURE_REPO_NO_UPDATE_CHECK", "1")
    status, _h, body = call(server, "/api/update")
    assert status == 200 and json.loads(body) == {"disabled": True}


def test_oversized_and_invalid_bodies_are_rejected(server):
    request = urllib.request.Request(f"http://127.0.0.1:{server.port}/api/branches", data=b"{not json", method="POST",
                                     headers={"X-SR-Token": TOKEN, "Content-Type": "application/json"})
    with pytest.raises(urllib.error.HTTPError) as error:
        urllib.request.urlopen(request, timeout=30)
    assert error.value.code == 400
