"""Builds (and rebuilds after triage) the summary, structure risk map and compliance of a report."""

from __future__ import annotations

from typing import Dict, List

from secure_repo.core import compliance
from secure_repo.core.models import OWASP_TOP10, SEVERITIES, SEVERITY_RANK, SUPPRESSED_STATUSES
from secure_repo.core.rules import RULES_BY_ID
from secure_repo.core.scoring import compute_score


def reportable(finding: Dict) -> bool:
    return finding.get("status", "open") not in SUPPRESSED_STATUSES


def annotate_structure(structure: Dict, findings: List[Dict]) -> None:
    index: Dict[str, Dict] = {}
    parents: Dict[str, List[Dict]] = {}

    def walk(node: Dict, chain: List[Dict]) -> None:
        node["findings"], node["risk"], node["severity"] = 0, None, {}
        index[node["path"]] = node
        parents[node["path"]] = chain
        for child in node.get("children", []):
            walk(child, chain + [node])

    walk(structure, [])
    for finding in findings:
        if not reportable(finding):
            continue
        path = finding.get("file") or ""
        node = index.get(path)
        chain = parents.get(path, [])
        if node is None:  # collapsed file nodes: attribute to the deepest known directory
            probe = path
            while "/" in probe and probe not in index:
                probe = probe.rsplit("/", 1)[0]
            node = index.get(probe, structure)
            chain = parents.get(node["path"], [])
        targets = [structure] if path in ("", ".") else chain + [node]
        for target in {id(t): t for t in targets}.values():
            severity = finding["severity"]
            target["findings"] += 1
            target["severity"][severity] = target["severity"].get(severity, 0) + 1
            if target["risk"] is None or SEVERITY_RANK[severity] < SEVERITY_RANK[target["risk"]]:
                target["risk"] = severity


def build_summary(report: Dict) -> None:
    findings = report["findings"]
    active = [f for f in findings if reportable(f)]
    by_severity = {s: 0 for s in SEVERITIES}
    by_category: Dict[str, int] = {}
    by_owasp: Dict[str, int] = {}
    by_status: Dict[str, int] = {}
    by_engine: Dict[str, int] = {}
    per_file: Dict[str, Dict] = {}
    for finding in findings:
        by_status[finding.get("status", "open")] = by_status.get(finding.get("status", "open"), 0) + 1
    for finding in active:
        by_severity[finding["severity"]] += 1
        by_category[finding["category"]] = by_category.get(finding["category"], 0) + 1
        by_owasp[finding["owasp"]] = by_owasp.get(finding["owasp"], 0) + 1
        by_engine[finding.get("engine", "pattern")] = by_engine.get(finding.get("engine", "pattern"), 0) + 1
        entry = per_file.setdefault(finding["file"], {"file": finding["file"], "count": 0, "risk": finding["severity"]})
        entry["count"] += 1
        if SEVERITY_RANK[finding["severity"]] < SEVERITY_RANK[entry["risk"]]:
            entry["risk"] = finding["severity"]
    score = compute_score(findings)
    summary = report.setdefault("summary", {})
    summary.update({
        "findings": len(active), "by_severity": by_severity,
        "by_category": dict(sorted(by_category.items(), key=lambda kv: -kv[1])),
        "by_owasp": {k: by_owasp[k] for k in OWASP_TOP10 if k in by_owasp},
        "by_status": by_status, "by_engine": by_engine,
        "suppressed": sum(1 for f in findings if not reportable(f)),
        "score": score["score"], "grade": score["grade"],
        "top_files": sorted(per_file.values(), key=lambda e: (SEVERITY_RANK[e["risk"]], -e["count"]))[:15],
    })


def finalize(report: Dict, custom_rules: Dict[str, Dict] = None) -> None:
    """Recompute everything derived from the findings list (used after scanning and after triage)."""
    build_summary(report)
    annotate_structure(report["structure"], report["findings"])
    rules = dict(report.get("rules") or {})
    for rule_id in {f["rule_id"] for f in report["findings"]}:
        if rule_id in RULES_BY_ID:
            rules[rule_id] = RULES_BY_ID[rule_id].to_dict()
        elif custom_rules and rule_id in custom_rules:
            rules[rule_id] = custom_rules[rule_id]
    report["rules"] = rules
    options = report["meta"].get("options", {})
    if options.get("compliance"):
        active = [f for f in report["findings"] if reportable(f)]
        report["compliance"] = compliance.evaluate(active, report.get("hygiene", {}), options.get("frameworks") or ["all"])
    else:
        report["compliance"] = {"enabled": False, "frameworks": []}
