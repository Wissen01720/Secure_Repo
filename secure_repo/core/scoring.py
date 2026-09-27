"""Security score (0-100) and letter grade."""

from __future__ import annotations

import math
from typing import Dict, List

from secure_repo.core.models import SEVERITY_WEIGHT, SUPPRESSED_STATUSES

GRADES = [(90, "A"), (75, "B"), (60, "C"), (40, "D"), (0, "F")]


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
    score = int(round(100 * math.exp(-penalty / 60.0)))
    grade = next(letter for threshold, letter in GRADES if score >= threshold)
    return {"score": score, "grade": grade, "penalty": round(penalty, 2)}
