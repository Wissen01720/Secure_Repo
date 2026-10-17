"""Security score (0-100) and letter grade."""

from __future__ import annotations

import math

from secure_repo.core.models import SEVERITY_WEIGHT, SUPPRESSED_STATUSES

GRADES = [(90, "A"), (75, "B"), (60, "C"), (40, "D"), (0, "F")]
CAP_CRITICAL = 59  # highest score (grade D) allowed while a critical finding is open
CAP_HIGH = 74      # highest score (grade C) allowed while a high-severity finding is open
SURFACE = 0.25     # extra penalty per e-fold of distinct files a weakness appears in (attack surface)


def compute_score(findings: list[dict]) -> dict:
    per_rule: dict[str, dict] = {}
    for finding in findings:
        status = finding.get("status", "open")
        if status in SUPPRESSED_STATUSES:
            continue  # false positives and filtered findings never affect the score
        extra = finding.get("extra") or {}
        factor = 0.5 if (finding.get("in_test") or extra.get("third_party") or extra.get("example_block")) else 1.0
        if status == "accepted_risk":
            factor *= 0.5  # documented, owned risk still counts, at half weight
        bucket = per_rule.setdefault(finding["rule_id"], {"weight": 0.0, "count": 0.0, "files": set()})
        bucket["weight"] = max(bucket["weight"], SEVERITY_WEIGHT.get(finding["severity"], 0.0))
        bucket["count"] += factor
        bucket["files"].add(finding.get("file", ""))
    penalty = 0.0
    for bucket in per_rule.values():
        if bucket["weight"] and bucket["count"]:
            # Repeated occurrences of the same weakness add diminishing penalty, but the same flaw spread over many
            # files is a wider attack surface than the same flaw repeated in one file.
            breadth = 1.0 + SURFACE * math.log(len(bucket["files"])) if len(bucket["files"]) > 1 else 1.0
            penalty += (bucket["weight"] * (1 + math.log(max(bucket["count"], 1.0))) * min(1.0, bucket["count"])
                        * breadth)
    raw_score = int(round(100 * math.exp(-penalty / 60.0)))
    score = raw_score
    # A repository with an open critical finding must never look "acceptable": cap the grade (production code only).
    blocking = [f for f in findings
                if f.get("status", "open") not in SUPPRESSED_STATUSES + ("accepted_risk",) and not f.get("in_test")
                and not (f.get("extra") or {}).get("third_party") and not (f.get("extra") or {}).get("example_block")]
    criticals = sum(1 for f in blocking if f["severity"] == "critical")
    highs = sum(1 for f in blocking if f["severity"] == "high")
    cap = None
    if criticals and raw_score > CAP_CRITICAL:
        score, cap = CAP_CRITICAL, {"grade": "D", "reason": f"{criticals} open critical finding(s)"}
    elif not criticals and highs and raw_score > CAP_HIGH:
        score, cap = CAP_HIGH, {"grade": "C", "reason": f"{highs} open high-severity finding(s)"}
    grade = next(letter for threshold, letter in GRADES if score >= threshold)
    result = {"score": score, "grade": grade, "penalty": round(penalty, 2), "uncapped_score": raw_score,
              "uncapped_grade": next(letter for threshold, letter in GRADES if raw_score >= threshold), "cap": None}
    if cap:
        cap["message"] = f"Grade limited to {cap['grade']} because of {cap['reason']} (uncapped score: {raw_score})"
        result["cap"] = cap
    return result
