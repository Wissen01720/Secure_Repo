"""Builds a single self-contained HTML report by inlining the GUI assets."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from typing import Dict

STATIC_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "gui", "static")
# Scripts are allowed by SHA-256 hash only: anything injected later (an escaping bug, an edited file) will not run.
# Styles stay 'unsafe-inline' (the page sets inline style attributes; CSS cannot execute code).
REPORT_CSP_TEMPLATE = ("default-src 'none'; script-src {hashes}; style-src 'unsafe-inline'; "
                       "img-src data: blob:; font-src data:; connect-src 'none'; form-action 'none'; base-uri 'none'")
_INLINE_SCRIPT = re.compile(r"<script>(.*?)</script>", re.DOTALL)


def script_hashes(html: str) -> str:
    """CSP source list ('sha256-...') covering every inline <script> block of the page."""
    sources = []
    for match in _INLINE_SCRIPT.finditer(html):
        digest = hashlib.sha256(match.group(1).encode("utf-8")).digest()
        token = "'sha256-" + base64.b64encode(digest).decode("ascii") + "'"
        if token not in sources:
            sources.append(token)
    return " ".join(sources) or "'none'"


def _read(name: str) -> str:
    with open(os.path.join(STATIC_DIR, name), encoding="utf-8") as handle:
        return handle.read()


def safe_json_for_script(data: Dict) -> str:
    text = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    return text.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026") \
        .replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")


def build_html_report(report: Dict) -> str:
    html = _read("index.html")
    css = _read("app.css")
    html = html.replace('<link rel="stylesheet" href="/static/app.css">', f"<style>\n{css}\n</style>")

    def inline_script(match: re.Match[str]) -> str:
        source = _read(match.group(1)).replace("</script", "<\\/script")
        return f"<script>\n{source}\n</script>"

    html = re.sub(r'<script src="/static/([\w.-]+\.js)"></script>', inline_script, html)
    data = f"<script>window.__SR_REPORT__ = {safe_json_for_script(report)};</script>"
    html = html.replace("<!-- SR:REPORT-DATA -->", data)
    policy = REPORT_CSP_TEMPLATE.format(hashes=script_hashes(html))
    csp = f'<meta http-equiv="Content-Security-Policy" content="{policy}">'
    html = html.replace("<!-- SR:REPORT-CSP -->", csp)
    title = f"Secure Repo report - {report['meta']['name']}"
    html = re.sub(r"<title>.*?</title>", lambda _m: f"<title>{_escape(title)}</title>", html, count=1)
    return html


def _escape(text: str) -> str:
    return (text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;"))
