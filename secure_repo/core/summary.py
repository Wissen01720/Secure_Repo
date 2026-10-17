"""Builds (and rebuilds after triage) the summary, structure risk map and compliance of a report."""

from __future__ import annotations


from secure_repo.core import compliance
from secure_repo.core.languages import DOCUMENTATION
from secure_repo.core.models import OWASP_TOP10, REPO_CONTROLLED_ORIGINS, SEVERITIES, SEVERITY_RANK, SUPPRESSED_STATUSES
from secure_repo.core.rules import RULES_BY_ID
from secure_repo.core.scoring import compute_score


def reportable(finding: dict) -> bool:
    return finding.get("status", "open") not in SUPPRESSED_STATUSES


def annotate_structure(structure: dict, findings: list[dict]) -> None:
    index: dict[str, dict] = {}
    parents: dict[str, list[dict]] = {}

    def walk(node: dict, chain: list[dict]) -> None:
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


def _brief(score: dict) -> dict:
    return {"score": score["score"], "grade": score["grade"], "cap": score["cap"]}


def split_scores(report: dict, findings: list[dict]) -> dict:
    """Three numbers instead of one: production code, test code, and findings per thousand lines of code.

    The headline score mixes everything (tests count half). On its own it saturates on big projects and cannot tell a
    mature framework from a deliberately vulnerable app, so the report also shows how the production code scores by
    itself and how dense the findings are relative to the size of the code base.
    """
    production = compute_score([f for f in findings if not f.get("in_test")])
    in_tests = compute_score([f for f in findings if f.get("in_test")])
    code_lines = sum(entry.get("lines", 0) for language, entry in (report.get("languages") or {}).items()
                     if language not in DOCUMENTATION)
    kloc = code_lines / 1000.0
    own = [f for f in findings if reportable(f) and not f.get("in_test") and f.get("source") in ("code", "secret")]
    serious = [f for f in own if f["severity"] in ("critical", "high")]
    return {
        "production": _brief(production), "tests": _brief(in_tests),
        "density": {"kloc": round(kloc, 1), "findings": len(own), "serious": len(serious),
                    "per_kloc": round(len(own) / kloc, 2) if kloc else None,
                    "serious_per_kloc": round(len(serious) / kloc, 2) if kloc else None},
    }


def build_summary(report: dict) -> None:
    findings = report["findings"]
    active = [f for f in findings if reportable(f)]
    by_severity = {s: 0 for s in SEVERITIES}
    by_category: dict[str, int] = {}
    by_owasp: dict[str, int] = {}
    by_status: dict[str, int] = {}
    by_engine: dict[str, int] = {}
    per_file: dict[str, dict] = {}
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
    influence = (report.get("analysis") or {}).get("repo_influence")
    if influence is not None:
        shadow = []
        touched = 0
        for finding in findings:
            copy = dict(finding)
            if (finding.get("triage") or {}).get("origin") in REPO_CONTROLLED_ORIGINS:
                copy["status"] = "open"
                touched += 1
            extra = finding.get("extra") or {}
            if extra.get("severity_override_origin") == "repo":
                copy["severity"] = extra["original_severity"]
                touched += 1
            shadow.append(copy)
        alternative = compute_score(shadow)
        influence.update({
            "score_with_repo_content": score["score"], "grade_with_repo_content": score["grade"],
            "score_without_repo_content": alternative["score"], "grade_without_repo_content": alternative["grade"],
            "findings_affected": touched,
            "material": alternative["grade"] != score["grade"] or alternative["score"] - score["score"] >= 10,
            "active": bool(touched or influence["excluded_by_config"]["files"] or influence["ignored"]),
        })
    summary = report.setdefault("summary", {})
    summary["scores"] = split_scores(report, findings)
    marked = [f for f in findings if (f.get("extra") or {}).get("baseline")]
    if marked:
        fresh = [f for f in marked if f["extra"]["baseline"] == "new" and reportable(f)]
        summary["baseline"] = {"new": len(fresh), "existing": len([f for f in marked if f["extra"]["baseline"] == "existing"
                                                                   and reportable(f)]),
                               "new_by_severity": {s: sum(1 for f in fresh if f["severity"] == s) for s in SEVERITIES}}
    else:
        summary.pop("baseline", None)
    summary.update({
        "findings": len(active), "by_severity": by_severity,
        "by_category": dict(sorted(by_category.items(), key=lambda kv: -kv[1])),
        "by_owasp": {k: by_owasp[k] for k in OWASP_TOP10 if k in by_owasp},
        "by_status": by_status, "by_engine": by_engine,
        "suppressed": sum(1 for f in findings if not reportable(f)),
        "score": score["score"], "grade": score["grade"], "grade_cap": score["cap"],
        "uncapped_score": score["uncapped_score"],
        "top_files": sorted(per_file.values(), key=lambda e: (SEVERITY_RANK[e["risk"]], -e["count"]))[:15],
    })


def finalize(report: dict, custom_rules: dict[str, dict] = None) -> None:
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
