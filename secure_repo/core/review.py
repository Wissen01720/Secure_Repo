"""Triage operations shared by the CLI and the GUI (mark, learn, recompute, refresh reports)."""

from __future__ import annotations

import getpass

from secure_repo.core import summary as summarymod
from secure_repo.core.models import TRIAGE_STATUSES
from secure_repo.core.triage import KnowledgeBase, project_key

SCOPES = {
    "finding": "only this finding",
    "project-pattern": "this code pattern anywhere in this project",
    "global-pattern": "this code pattern in every project",
}


def _author(author: str | None) -> str:
    """Who took the decision: explicit name, else the Git identity, else the OS account."""
    if author:
        return author
    try:
        import subprocess

        name = subprocess.run(["git", "config", "user.name"], capture_output=True, text=True, timeout=5,
                              stdin=subprocess.DEVNULL).stdout.strip()
        if name:
            return name
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        return getpass.getuser()
    except Exception:
        return ""


def triage(report: dict, finding_ids: list[str], status: str, reason: str = "", scope: str = "finding",
           author: str = "", knowledge: KnowledgeBase | None = None, report_dir: str | None = None) -> dict:
    """Record a decision for one or more findings, re-apply learning and refresh the report in place."""
    if status not in TRIAGE_STATUSES:
        raise ValueError(f"Unknown status '{status}'. Use: {', '.join(TRIAGE_STATUSES)}")
    if scope not in SCOPES:
        raise ValueError(f"Unknown scope '{scope}'. Use: {', '.join(SCOPES)}")
    if status == "false_positive" and not reason.strip():
        raise ValueError("A reason is required to mark a false positive (it is part of the audit trail).")
    knowledge = knowledge or KnowledgeBase()
    key, name = project_key(report["meta"])
    by_id = {f["id"]: f for f in report["findings"]}
    who = _author(author)
    changed = []
    for finding_id in finding_ids:
        finding = by_id.get(finding_id.strip().upper())
        if finding is None:
            raise ValueError(f"Finding {finding_id} not found")
        knowledge.record(key, name, finding, status, reason, scope, who)
        finding["status"] = status
        finding["triage"] = {} if status == "open" else {"reason": reason, "author": who, "origin": "decision",
                                                          "scope": scope}
        changed.append(finding["id"])
    learned = 0
    if scope in ("project-pattern", "global-pattern"):
        pending = [f for f in report["findings"] if f.get("status") == "open"]
        learned = knowledge.apply(pending, key).get("learned_patterns", 0)
    summarymod.finalize(report)
    if report_dir:
        from secure_repo.report.writer import refresh_reports

        refresh_reports(report, report_dir, f"{', '.join(changed)} -> {status} ({SCOPES[scope]}) by {who or 'unknown'}"
                                            f": {reason}" + (f"; {learned} similar finding(s) suppressed" if learned else ""))
    return {"changed": changed, "learned": learned, "score": report["summary"]["score"],
            "grade": report["summary"]["grade"]}
