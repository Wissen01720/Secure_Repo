"""Writes (and refreshes after triage) the organized report folder produced by every scan."""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shutil
import zipfile
from datetime import datetime
from typing import Callable, Dict, List, Optional

from secure_repo.core.events import EventBus
from secure_repo.core.models import SEVERITIES
from secure_repo.core.summary import reportable
from secure_repo.core.walker import render_structure_text
from secure_repo.report import formats
from secure_repo.report.html import build_html_report

FOLDER_README = """SECURE REPO - REPORT FOLDER
===========================

Target : {target}
Branch : {branch}
Commit : {commit}
Date   : {date}
Score  : {score}/100 (grade {grade})

Contents
--------
report.html                     Interactive report (neural map, structure boxes, findings, libraries,
                                compliance). Open it in any browser - works offline.
report.json                     Complete machine-readable results.
report.sarif                    SARIF 2.1.0 - import into GitHub code scanning, Azure DevOps, IDEs.
summary.md                      Executive summary.
quality.md                      Analysis engines, noise discarded, confidence and suppressed findings.
findings/<severity>.md          Active findings in production code, grouped by severity, with explanation, data flow and fix.
findings/tests.md               Findings located in test code (reported apart, severity lowered one level).
findings/by-category/*.md       Active findings grouped by weakness category.
findings/suppressed.md          False positives / filtered findings with the reason (audit trail).
findings/findings.csv           Spreadsheet-friendly list of every finding and its triage status.
dependencies/inventory.csv      Every library detected (direct and transitive).
dependencies/inventory.json     Same inventory with advisories, licenses and latest versions.
dependencies/vulnerabilities.md Vulnerable libraries and advisories.
dependencies/virtual-lock.json  Versions resolved for dependencies without lockfile.
dependencies/lockfile-guide.md  How to create a real lockfile + proposed pins.
dependencies/sbom.cdx.json      CycloneDX 1.5 Software Bill of Materials.
structure/tree.txt              Repository tree annotated with findings.
structure/structure.json        Structure used by the box map.
structure/languages.md          Language statistics.
compliance/                     Compliance evidence per framework (only when the audit is enabled).
logs/scan.log                   Chronological log of every step performed (and every triage decision).
MANIFEST.sha256                 SHA-256 of every file (integrity / chain of custody).

Handle this folder as CONFIDENTIAL: it describes security weaknesses of the target.
Secrets are redacted, but locations of weaknesses are included.
"""


def _slug(value: str, limit: int = 40) -> str:
    value = re.sub(r"[^A-Za-z0-9._-]+", "-", value or "").strip("-.")
    return (value or "repo")[:limit]


def _write(path: str, content, binary: bool = False) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if binary:
        with open(path, "wb") as handle:
            handle.write(content)
    else:
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)


def _exclude_from_enclosing_repo(base: str) -> None:
    """If the reports folder sits inside a Git work tree, also list it in .git/info/exclude.

    The folder's own .gitignore does not stop `git add -f`; the exclude file lives outside the work tree content
    and is honoured by every Git front end.
    """
    current = base
    while True:
        git_dir = os.path.join(current, ".git")
        if os.path.isdir(git_dir):
            rel = os.path.relpath(base, current).replace(os.sep, "/")
            if rel in (".", "") or rel.startswith(".."):
                return
            entry = "/" + rel + "/"
            exclude = os.path.join(git_dir, "info", "exclude")
            try:
                existing = ""
                if os.path.exists(exclude):
                    with open(exclude, encoding="utf-8") as handle:
                        existing = handle.read()
                if entry not in existing.splitlines():
                    os.makedirs(os.path.dirname(exclude), exist_ok=True)
                    with open(exclude, "a", encoding="utf-8", newline="\n") as handle:
                        prefix = "" if existing.endswith("\n") or not existing else "\n"
                        handle.write(prefix + "# Secure Repo reports (never commit)\n" + entry + "\n")
            except OSError:
                pass
            return
        parent = os.path.dirname(current)
        if parent == current:
            return
        current = parent


def ensure_output_root(output_dir: str) -> str:
    base = os.path.abspath(os.path.expanduser(output_dir))
    os.makedirs(base, exist_ok=True)
    _exclude_from_enclosing_repo(base)
    guard = os.path.join(base, ".gitignore")
    if not os.path.exists(guard):
        _write(guard, "# Created by Secure Repo: security reports must never be committed.\n*\n")
    return base


def _write_contents(report: Dict, folder: str, tree_text: str, log_lines: List[str],
                    emit: Callable[[str], None]) -> None:
    meta = report["meta"]

    def out(rel: str, content) -> None:
        _write(os.path.join(folder, *rel.split("/")), content)
        emit(rel)

    everything = [f for f in report["findings"] if reportable(f)]
    active = [f for f in everything if not f.get("in_test")]          # production code
    in_tests = [f for f in everything if f.get("in_test")]            # reported apart, one severity level lower
    out("report.json", json.dumps(report, indent=2, ensure_ascii=False))
    out("report.html", build_html_report(report))
    out("report.sarif", json.dumps(formats.sarif(report), indent=2, ensure_ascii=False))
    out("summary.md", formats.markdown_summary(report))
    out("quality.md", formats.markdown_quality(report))

    for severity in SEVERITIES:
        subset = [f for f in active if f["severity"] == severity]
        out(f"findings/{severity}.md", formats.markdown_findings(report, subset, f"{severity.title()} findings"))
    categories: Dict[str, List[Dict]] = {}
    for finding in active:
        categories.setdefault(finding["category"], []).append(finding)
    shutil.rmtree(os.path.join(folder, "findings", "by-category"), ignore_errors=True)
    for category, subset in categories.items():
        out(f"findings/by-category/{_slug(category.lower(), 60)}.md", formats.markdown_findings(report, subset, category))
    out("findings/tests.md", formats.markdown_findings(report, sorted(in_tests, key=lambda f: SEVERITIES.index(f["severity"])),
                                                       "Findings in test code (severity lowered one level)"))
    out("findings/suppressed.md", formats.markdown_suppressed(report))
    out("findings/findings.csv", formats.findings_csv(report))

    out("dependencies/inventory.csv", formats.dependencies_csv(report))
    out("dependencies/inventory.json", json.dumps({"summary": report["dependency_summary"],
                                                   "dependencies": report["dependencies"]}, indent=2, ensure_ascii=False))
    out("dependencies/vulnerabilities.md", formats.markdown_dependencies(report))
    out("dependencies/virtual-lock.json", json.dumps(report.get("lockfile", {}), indent=2, ensure_ascii=False))
    out("dependencies/lockfile-guide.md", formats.markdown_lockfile_guide(report))
    out("dependencies/sbom.cdx.json", json.dumps(formats.cyclonedx(report), indent=2, ensure_ascii=False))

    out("structure/tree.txt", tree_text or "")
    out("structure/structure.json", json.dumps(report["structure"], ensure_ascii=False))
    out("structure/languages.md", formats.languages_markdown(report))

    shutil.rmtree(os.path.join(folder, "compliance"), ignore_errors=True)
    if report["compliance"].get("enabled"):
        out("compliance/compliance.json", json.dumps(report["compliance"], indent=2, ensure_ascii=False))
        for framework in report["compliance"]["frameworks"]:
            out(f"compliance/{framework['id']}.md", formats.markdown_compliance(report, framework))

    out("logs/scan.log", "\n".join(log_lines or []) + "\n")
    out("README.txt", FOLDER_README.format(
        target=meta["target"], branch=meta.get("branch") or "n/a", commit=meta.get("commit") or "n/a",
        date=meta["started_at"], score=report["summary"]["score"], grade=report["summary"]["grade"]))

    manifest_lines = []
    for current, _dirs, names in os.walk(folder):
        for name in sorted(names):
            if name == "MANIFEST.sha256":
                continue
            full = os.path.join(current, name)
            rel = os.path.relpath(full, folder).replace(os.sep, "/")
            with open(full, "rb") as handle:
                manifest_lines.append(f"{hashlib.sha256(handle.read()).hexdigest()}  {rel}")
    _write(os.path.join(folder, "MANIFEST.sha256"), "\n".join(sorted(manifest_lines, key=lambda entry: entry[66:])) + "\n")
    emit("MANIFEST.sha256")


def write_reports(report: Dict, output_dir: str, bus: Optional[EventBus] = None, tree_text: str = "",
                  log_lines: Optional[List[str]] = None) -> str:
    base = ensure_output_root(output_dir)
    meta = report["meta"]
    now = datetime.now()
    stamp = now.strftime("%Y%m%d-%H%M%S") + f"-{now.microsecond // 1000:03d}"  # milliseconds: names sort by time
    base_folder = os.path.join(base, f"{_slug(meta['name'])}_{_slug(meta.get('branch') or 'no-branch')}_{stamp}")
    folder, suffix = base_folder, 1
    while os.path.exists(folder):
        suffix += 1
        folder = f"{base_folder}-{suffix}"

    def emit(name: str) -> None:
        if bus:
            bus.log(f"Wrote {name}", "ok")

    _write_contents(report, folder, tree_text, log_lines or [], emit)
    _write(os.path.join(base, "latest.txt"), os.path.basename(folder) + "\n")  # the newest report, no sorting needed
    return folder


def refresh_reports(report: Dict, folder: str, log_entry: str = "") -> None:
    """Regenerate every artifact of an existing report folder (after triage decisions)."""
    def read(rel: str) -> str:
        try:
            with open(os.path.join(folder, *rel.split("/")), encoding="utf-8") as handle:
                return handle.read()
        except OSError:
            return ""

    log_lines = [line for line in read("logs/scan.log").splitlines() if line]
    if log_entry:
        log_lines.append(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} [TRIAG] {log_entry}")
    _write_contents(report, folder, render_structure_text(report["structure"]), log_lines, lambda _name: None)


def zip_folder(folder: str) -> bytes:
    buffer = io.BytesIO()
    root_name = os.path.basename(folder.rstrip(os.sep))
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for current, _dirs, names in os.walk(folder):
            for name in names:
                full = os.path.join(current, name)
                archive.write(full, os.path.join(root_name, os.path.relpath(full, folder)))
    return buffer.getvalue()
