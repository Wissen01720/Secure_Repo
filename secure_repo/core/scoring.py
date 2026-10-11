"""Security score (0-100) and letter grade."""

from __future__ import annotations

import math
from typing import Dict, List

from secure_repo.core.models import SEVERITY_WEIGHT, SUPPRESSED_STATUSES

GRADES = [(90, "A"), (75, "B"), (60, "C"), (40, "D"), (0, "F")]
CAP_CRITICAL = 59  # highest score (grade D) allowed while a critical finding is open
CAP_HIGH = 74      # highest score (grade C) allowed while a high-severity finding is open


def compute_score(findings: List[Dict]) -> Dict:
    per_rule: Dict[str, Dict] = {}
    for finding in findings:
        status = finding.get("status", "open")
        if status in SUPPRESSED_STATUSES:
            continue  # false positives and filtered findings never affect the score
        factor = 0.5 if finding.get("in_test") else 1.0
        if status == "accepted_risk":
            factor *= 0.5  # documented, owned risk still counts, at half weight
        bucket = per_rule.setdefault(finding["rule_id"], {"weight": 0.0, "count": 0.0})
        bucket["weight"] = max(bucket["weight"], SEVERITY_WEIGHT.get(finding["severity"], 0.0))
        bucket["count"] += factor
    penalty = 0.0
    for bucket in per_rule.values():
        if bucket["weight"] and bucket["count"]:
            # Repeated occurrences of the same weakness add diminishing penalty.
            penalty += bucket["weight"] * (1 + math.log(max(bucket["count"], 1.0))) * min(1.0, bucket["count"])
    raw_score = int(round(100 * math.exp(-penalty / 60.0)))
    score = raw_score
    # A repository with an open critical finding must never look "acceptable": cap the grade (production code only).
    blocking = [f for f in findings
                if f.get("status", "open") not in SUPPRESSED_STATUSES + ("accepted_risk",) and not f.get("in_test")]
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
