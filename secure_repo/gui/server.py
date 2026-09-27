"""Local GUI server.

Security model:
* binds to 127.0.0.1 only, on a random free port by default;
* every API call requires a random per-session token (delivered in the URL fragment,
  which browsers never send to servers or log);
* the Host header is validated to defeat DNS-rebinding attacks;
* strict Content-Security-Policy, no third-party resources, no inline scripts.
"""

from __future__ import annotations

import hmac
import json
import os
import platform
import re
import secrets
import sys
import threading
import time
import uuid
import webbrowser
from dataclasses import replace
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, List, Optional
from urllib.parse import parse_qs, urlparse

from rich.panel import Panel
from rich.text import Text

from secure_repo import __author__, __version__
from secure_repo.cli.theme import CYAN, DIM, MAGENTA, NEON, console, say
from secure_repo.core import compliance, gitops
from secure_repo.core.events import STAGES, EventBus
from secure_repo.core.rules import RULES
from secure_repo.core.scanner import ScanCancelled, Scanner, ScanOptions
from secure_repo.core.workspace import Target, discover_branches
from secure_repo.report.writer import ensure_output_root, zip_folder

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
MIME = {".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8",
        ".js": "application/javascript; charset=utf-8", ".svg": "image/svg+xml", ".json": "application/json"}
CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; "
       "connect-src 'self'; font-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
DOWNLOADS = {
    "html": ("report.html", "text/html; charset=utf-8"),
    "json": ("report.json", "application/json"),
    "sarif": ("report.sarif", "application/sarif+json"),
    "md": ("summary.md", "text/markdown; charset=utf-8"),
    "sbom": ("dependencies/sbom.cdx.json", "application/vnd.cyclonedx+json"),
    "csv": ("findings/findings.csv", "text/csv; charset=utf-8"),
    "deps": ("dependencies/inventory.csv", "text/csv; charset=utf-8"),
}
MAX_BODY = 1024 * 1024


class ScanJob:
    def __init__(self, job_id: str, target: Optional[Target] = None):
        self.id = job_id
        self.target = target
        self.events: List[str] = []
        self.cond = threading.Condition()
        self.status = "running"
        self.report: Optional[Dict] = None
        self.report_dir: Optional[str] = None
        self.error: Optional[str] = None
        self.scanner: Optional[Scanner] = None
        self.created = time.time()

    def push(self, event: Dict) -> None:
        data = json.dumps(event, default=str, ensure_ascii=False)
        with self.cond:
            self.events.append(data)
            self.cond.notify_all()

    def finish(self, status: str) -> None:
        with self.cond:
            self.status = status
            self.cond.notify_all()


class AppState:
    def __init__(self, options: ScanOptions, token: str):
        self.options = options
        self.token = token
        self.jobs: Dict[str, ScanJob] = {}
        self.port = 0
        self.cwd = os.getcwd()
        self.preload: Optional[str] = None
        self.lock = threading.Lock()


def _run_job(state: AppState, job: ScanJob, target: Target, options: ScanOptions) -> None:
    bus = EventBus()
    bus.subscribe(job.push)
    job.scanner = Scanner(options, bus)
    try:
        report, report_dir = job.scanner.run(target, interactive=False)
        job.report, job.report_dir = report, report_dir
        job.push({"type": "complete", "ts": time.time(), "scan_id": job.id, "report_dir": report_dir})
        job.finish("done")
    except ScanCancelled:
        job.push({"type": "failed", "ts": time.time(), "message": "Scan cancelled"})
        job.finish("cancelled")
    except Exception as exc:
        job.error = str(exc)
        job.push({"type": "failed", "ts": time.time(), "message": str(exc)})
        job.finish("error")


class QuietServer(ThreadingHTTPServer):
    """Threaded server that ignores clients disconnecting (closed tabs, reloads)."""

    daemon_threads = True

    def handle_error(self, request, client_address) -> None:
        if isinstance(sys.exc_info()[1], (ConnectionError, TimeoutError)):
            return
        super().handle_error(request, client_address)


def make_handler(state: AppState):
    class Handler(BaseHTTPRequestHandler):
        server_version = "SecureRepo"
        sys_version = ""
        protocol_version = "HTTP/1.1"

        # ---------------------------------------------------------------- utils
        def log_message(self, fmt, *args):  # keep the terminal clean
            return

        def _security_headers(self, content_type: str) -> None:
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Cross-Origin-Opener-Policy", "same-origin")
            self.send_header("Cross-Origin-Resource-Policy", "same-origin")
            if content_type.startswith("text/html"):
                self.send_header("Content-Security-Policy", CSP)

        def _send(self, status: int, body: bytes, content_type: str, extra: Optional[Dict[str, str]] = None) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self._security_headers(content_type)
            for key, value in (extra or {}).items():
                self.send_header(key, value)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _json(self, data, status: int = 200) -> None:
            self._send(status, json.dumps(data, ensure_ascii=False, default=str).encode("utf-8"), "application/json")

        def _error(self, status: int, message: str) -> None:
            self._json({"error": message}, status)

        def _host_ok(self) -> bool:
            host = (self.headers.get("Host") or "").lower()
            return host in {f"127.0.0.1:{state.port}", f"localhost:{state.port}"}

        def _token_ok(self, query: Dict) -> bool:
            supplied = self.headers.get("X-SR-Token") or (query.get("token") or [""])[0]
            return bool(supplied) and hmac.compare_digest(supplied, state.token)

        def _body(self) -> Dict:
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY:
                raise ValueError("Request too large")
            raw = self.rfile.read(length) if length else b"{}"
            data = json.loads(raw.decode("utf-8") or "{}")
            if not isinstance(data, dict):
                raise ValueError("JSON object expected")
            return data

        def _job(self, job_id: str) -> Optional[ScanJob]:
            return state.jobs.get(job_id)

        # ---------------------------------------------------------------- routing
        def do_GET(self):
            self._dispatch("GET")

        def do_HEAD(self):
            self._dispatch("GET")

        def do_POST(self):
            if self.headers.get("Origin") not in (None, f"http://127.0.0.1:{state.port}", f"http://localhost:{state.port}"):
                return self._error(403, "Cross-origin request blocked")
            self._dispatch("POST")

        def _dispatch(self, method: str) -> None:
            if not self._host_ok():
                return self._error(421, "Invalid Host header")
            parsed = urlparse(self.path)
            path, query = parsed.path, parse_qs(parsed.query)
            try:
                if method == "GET" and path in ("/", "/index.html"):
                    return self._static("index.html")
                if method == "GET" and path.startswith("/static/"):
                    return self._static(path[len("/static/"):])
                if method == "GET" and path == "/favicon.ico":
                    return self._send(204, b"", "image/x-icon")
                if not path.startswith("/api/"):
                    return self._error(404, "Not found")
                if not self._token_ok(query):
                    return self._error(401, "Missing or invalid session token")
                return self._api(method, path, query)
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                return
            except ValueError as exc:
                return self._error(400, str(exc))
            except Exception as exc:  # pragma: no cover
                return self._error(500, f"Internal error: {exc}")

        def _static(self, name: str) -> None:
            if not re.fullmatch(r"[\w.-]+", name):
                return self._error(404, "Not found")
            full = os.path.join(STATIC_DIR, name)
            if not os.path.isfile(full):
                return self._error(404, "Not found")
            with open(full, "rb") as handle:
                body = handle.read()
            self._send(200, body, MIME.get(os.path.splitext(name)[1], "application/octet-stream"))

        def _api(self, method: str, path: str, query: Dict) -> None:
            parts = [p for p in path.split("/") if p][1:]  # drop "api"
            if method == "GET" and parts == ["context"]:
                return self._json(self._context())
            if method == "POST" and parts == ["branches"]:
                return self._branches(self._body())
            if method == "POST" and parts == ["scan"]:
                return self._start_scan(self._body())
            if len(parts) >= 3 and parts[0] == "scans":
                job = self._job(parts[1])
                if job is None:
                    return self._error(404, "Unknown scan")
                action = parts[2]
                if method == "GET" and action == "events":
                    return self._events(job)
                if method == "GET" and action == "report":
                    if not job.report:
                        return self._error(409, "Report not ready")
                    return self._json({"report": job.report, "report_dir": job.report_dir, "scan_id": job.id})
                if method == "GET" and action == "download" and len(parts) == 4:
                    return self._download(job, parts[3])
                if method == "POST" and action == "cancel":
                    if job.scanner:
                        job.scanner.cancelled = True
                    return self._json({"ok": True})
                if method == "POST" and action == "open-folder":
                    return self._open_folder(job)
            return self._error(404, "Unknown endpoint")

        # ---------------------------------------------------------------- endpoints
        def _context(self) -> Dict:
            root = gitops.find_repo_root(state.cwd)
            return {
                "version": __version__, "author": __author__, "cwd": state.cwd, "repo_root": root,
                "current_branch": gitops.current_branch(root) if root else None,
                "remote": gitops.remote_url(root) if root else "",
                "platform": f"{platform.system()} {platform.release()}", "python": platform.python_version(),
                "git": gitops.git_version(), "git_available": gitops.git_available(),
                "frameworks": compliance.list_frameworks(), "rules": len(RULES),
                "stages": [{"id": sid, "title": title} for sid, title in STAGES],
                "defaults": {"offline": state.options.offline, "compliance": state.options.compliance,
                             "include_tests": state.options.include_tests,
                             "max_file_size_kb": state.options.max_file_size // 1024},
                "output_dir": os.path.abspath(state.options.output_dir), "preload": state.preload,
            }

        def _target_from(self, data: Dict) -> Target:
            kind = data.get("kind")
            location = str(data.get("location") or "").strip()
            if kind == "remote":
                return Target("remote", gitops.validate_url(location))
            if kind in ("local", "current"):
                location = os.path.abspath(os.path.expanduser(location or state.cwd))
                if not os.path.isdir(location):
                    raise ValueError(f"Directory not found: {location}")
                return Target("local", location)
            raise ValueError("Unknown target kind")

        def _branches(self, data: Dict) -> None:
            try:
                target = self._target_from(data)
                branches = discover_branches(target, interactive=False)
            except gitops.GitError as exc:
                return self._error(400, f"Branch discovery failed: {exc}")
            return self._json({"target": target.location, "kind": target.kind, "git": bool(branches),
                               "branches": [b.to_dict() for b in branches]})

        def _start_scan(self, data: Dict) -> None:
            if data.get("authorized") is not True:
                return self._error(400, "You must confirm that you are authorized to audit this repository.")
            try:
                target = self._target_from(data)
            except gitops.GitError as exc:
                return self._error(400, str(exc))
            branch = data.get("branch")
            if branch:
                target.branch = gitops.validate_branch(str(branch))
            raw = data.get("options") or {}
            frameworks = [str(f) for f in raw.get("frameworks") or ["all"]][:20]
            max_kb = int(raw.get("max_file_size_kb") or state.options.max_file_size // 1024)
            options = replace(
                state.options, offline=bool(raw.get("offline", state.options.offline)),
                compliance=bool(raw.get("compliance", False)), frameworks=frameworks or ["all"],
                include_tests=bool(raw.get("include_tests", True)), enrich=bool(raw.get("enrich", True)),
                max_file_size=max(16, min(max_kb, 102400)) * 1024, auditor=str(raw.get("auditor") or "")[:120],
                exclude=[str(p)[:200] for p in (raw.get("exclude") or [])][:50])
            with state.lock:
                running = [j for j in state.jobs.values() if j.status == "running"]
                if len(running) >= 2:
                    return self._error(429, "Two scans are already running. Wait for them to finish.")
                job = ScanJob(uuid.uuid4().hex[:12], target)
                state.jobs[job.id] = job
            threading.Thread(target=_run_job, args=(state, job, target, options), daemon=True).start()
            console.print(Text.assemble(("[>] ", f"bold {MAGENTA}"), ("GUI scan started: ", "white"),
                                        (f"{target.location} @ {target.branch or 'default/working tree'}", CYAN)))
            return self._json({"scan_id": job.id})

        def _events(self, job: ScanJob) -> None:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Accel-Buffering", "no")
            self.send_header("Connection", "keep-alive")
            self._security_headers("text/event-stream")
            self.end_headers()
            index = int(self.headers.get("Last-Event-ID") or 0)
            while True:
                with job.cond:
                    if index >= len(job.events) and job.status == "running":
                        job.cond.wait(timeout=15)
                    batch = job.events[index:]
                    finished = job.status != "running"
                chunks = []
                for offset, data in enumerate(batch, index + 1):
                    chunks.append(f"id: {offset}\ndata: {data}\n\n")
                index += len(batch)
                if not chunks:
                    chunks.append(": keep-alive\n\n")
                if finished and index >= len(job.events):
                    chunks.append("event: end\ndata: {}\n\n")
                self.wfile.write("".join(chunks).encode("utf-8"))
                self.wfile.flush()
                if finished and index >= len(job.events):
                    self.close_connection = True
                    return

        def _download(self, job: ScanJob, kind: str) -> None:
            if not job.report_dir or not os.path.isdir(job.report_dir):
                return self._error(409, "Report folder not available")
            base = os.path.basename(job.report_dir.rstrip(os.sep))
            if kind == "zip":
                body = zip_folder(job.report_dir)
                return self._send(200, body, "application/zip",
                                  {"Content-Disposition": f'attachment; filename="{base}.zip"'})
            if kind not in DOWNLOADS:
                return self._error(404, "Unknown download")
            rel, mime = DOWNLOADS[kind]
            full = os.path.join(job.report_dir, *rel.split("/"))
            if not os.path.isfile(full):
                return self._error(404, "File not generated")
            with open(full, "rb") as handle:
                body = handle.read()
            filename = f"{base}_{os.path.basename(rel)}"
            return self._send(200, body, mime, {"Content-Disposition": f'attachment; filename="{filename}"'})

        def _open_folder(self, job: ScanJob) -> None:
            if not job.report_dir:
                return self._error(409, "Report folder not available")
            from secure_repo.cli.menu import open_path

            open_path(job.report_dir)
            return self._json({"ok": True, "path": job.report_dir})

    return Handler


def serve(options: ScanOptions, port: int = 0, open_browser: bool = True, preload_report: Optional[Dict] = None,
          preload_dir: Optional[str] = None) -> None:
    ensure_output_root(options.output_dir)
    token = secrets.token_urlsafe(32)
    state = AppState(options, token)
    if preload_report is not None:
        job = ScanJob("preloaded")
        job.report, job.report_dir, job.status = preload_report, preload_dir, "done"
        state.jobs[job.id] = job
        state.preload = job.id
    server = QuietServer(("127.0.0.1", port), make_handler(state))
    state.port = server.server_address[1]
    url = f"http://127.0.0.1:{state.port}/#token={token}"
    body = Text()
    body.append("GUI online at  ", style=DIM)
    body.append(url, style=f"bold {NEON}")
    body.append("\n\nListening on 127.0.0.1 only · session token required · Ctrl+C to stop\n", style=DIM)
    body.append("Reports folder: ", style=DIM)
    body.append(os.path.abspath(options.output_dir), style=CYAN)
    console.print(Panel(body, title=Text(" ⟦ SECURE//REPO · GRAPHICAL INTERFACE ⟧ ", style=f"bold {NEON}"),
                        border_style=MAGENTA, padding=(1, 2)))
    if open_browser:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever(poll_interval=0.3)
    except KeyboardInterrupt:
        console.print()
    finally:
        for job in state.jobs.values():
            if job.scanner and job.status == "running":
                job.scanner.cancelled = True
        server.server_close()
        say("GUI server stopped.", "ok")
