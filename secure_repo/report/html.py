"""Builds a single self-contained HTML report by inlining the GUI assets."""

from __future__ import annotations

import json
import os
import re
from typing import Dict

STATIC_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "gui", "static")
REPORT_CSP = ("default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
              "img-src data: blob:; font-src data:; connect-src 'none'; form-action 'none'; base-uri 'none'")


def _read(name: str) -> str:
    with open(os.path.join(STATIC_DIR, name), "r", encoding="utf-8") as handle:
        return handle.read()


def safe_json_for_script(data: Dict) -> str:
    text = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    return text.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026") \
        .replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")


def build_html_report(report: Dict) -> str:
    html = _read("index.html")
    css = _read("app.css")
    html = html.replace('<link rel="stylesheet" href="/static/app.css">', f"<style>\n{css}\n</style>")

    def inline_script(match: "re.Match[str]") -> str:
        source = _read(match.group(1)).replace("</script", "<\\/script")
        return f"<script>\n{source}\n</script>"

    html = re.sub(r'<script src="/static/([\w.-]+\.js)"></script>', inline_script, html)
    data = f"<script>window.__SR_REPORT__ = {safe_json_for_script(report)};</script>"
    csp = f'<meta http-equiv="Content-Security-Policy" content="{REPORT_CSP}">'
    html = html.replace("<!-- SR:REPORT-DATA -->", data).replace("<!-- SR:REPORT-CSP -->", csp)
    title = f"Secure Repo report - {report['meta']['name']}"
    html = re.sub(r"<title>.*?</title>", lambda _m: f"<title>{_escape(title)}</title>", html, count=1)
    return html


def _escape(text: str) -> str:
    return (text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;"))
