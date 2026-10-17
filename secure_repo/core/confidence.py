"""Confidence model: how likely a finding is a true positive.

The score (0-100) combines the rule's base precision, the analysis engine that produced the
finding (taint-confirmed > syntax tree > lexical > pattern), the location (tests, examples,
generated code) and - the learning part - the triage history of the rule in your own code bases.
"""

from __future__ import annotations

import re

BASE = {"high": 80, "medium": 60, "low": 40}
LEVELS = (("high", 70), ("medium", 45), ("low", 0))
DOC_PATH = re.compile(r"(?i)(^|/)(docs?|examples?|samples?|demos?|tutorials?|fixtures?|mocks?|stubs?|__mocks__|"
                      r"testdata|benchmarks?)(/|$)")
GENERATED = re.compile(r"(?i)(\.min\.|\.pb\.go$|_pb2\.py$|\.generated\.|(^|/)generated/|(^|/)gen/)")
# Rules that only deserve high confidence when a data flow from an untrusted source was confirmed.
NEEDS_TAINT = {"SR-PY-011"}
ENGINE_BONUS = {"taint": (20, "untrusted data flow confirmed from source to sink"),
                "ast": (10, "confirmed by syntax-tree analysis"),
                "lexical": (5, "comments and string literals excluded"),
                "dependency": (10, "matched against vulnerability databases"),
                "hygiene": (10, "repository-level fact")}


def label(score: int) -> str:
    return next(name for name, threshold in LEVELS if score >= threshold)


def assess(finding: dict, knowledge=None) -> None:
    score = BASE.get(finding.get("confidence", "medium"), 60)
    reasons = []
    bonus = ENGINE_BONUS.get(finding.get("engine", "pattern"))
    if bonus:
        score += bonus[0]
        reasons.append(bonus[1])
    path = finding.get("file") or ""
    signals = finding.get("extra") or {}
    if finding.get("rule_id") in NEEDS_TAINT and finding.get("engine") != "taint":
        score = min(score, 69)
        reasons.append("no untrusted source was confirmed, so confidence is capped at medium")
    if signals.get("internal_sql"):
        score -= 30
        reasons.append("only internal identifiers (self.*, quote_name(), numbers) are interpolated")
    if signals.get("third_party"):
        score -= 30
        reasons.append(f"bundled third-party library ({signals['third_party']}): update it instead of editing it")
    if signals.get("example_block"):
        score -= 25
        reasons.append("inside a <pre>/<code> block: a documentation example, not executed code")
    if finding.get("in_test"):
        score -= 15
        reasons.append("located in test code")
    if DOC_PATH.search(path):
        score -= 20
        reasons.append("located in an example/documentation path")
    if GENERATED.search(path):
        score -= 15
        reasons.append("generated or minified file")
    if knowledge is not None:
        total, ratio = knowledge.rule_quality(finding["rule_id"])
        if total >= 3 and ratio >= 0.6:
            score -= 25
            reasons.append(f"rule marked as false positive in {round(ratio * 100)}% of your triage decisions")
        elif total >= 3 and ratio <= 0.1:
            score += 10
            reasons.append("rule consistently confirmed in your triage history")
    score = max(5, min(99, score))
    finding["confidence_score"] = score
    finding["confidence"] = label(score)
    finding.setdefault("extra", {})["confidence_reasons"] = reasons


def meets(finding: dict, minimum: str | None) -> bool:
    if not minimum or minimum == "low":
        return True
    order = {"low": 0, "medium": 1, "high": 2}
    return order.get(finding.get("confidence", "low"), 0) >= order.get(minimum, 0)
