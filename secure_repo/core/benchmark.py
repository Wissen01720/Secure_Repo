"""Precision/recall benchmark of the detection engines against a labeled corpus.

Annotations inside corpus files:

* ``expect: SR-PY-001`` (or several ids separated by commas) on a line -> the rule must fire on that line;
* ``expect-none: SR-PY-009`` anywhere in the file -> the rule must not fire anywhere in the file.

Any other finding of a rule that is referenced by the file counts as a false positive; missing
expectations count as false negatives. Users can add their own cases (or export the false
positives they triaged with ``secure-repo triage export-cases``) to keep the engine honest.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from secure_repo.core.events import EventBus
from secure_repo.core.languages import detect_language
from secure_repo.core.scanner import Scanner, ScanOptions
from secure_repo.core.walker import FileInfo

CORPUS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "benchmark", "corpus")
EXPECT_RE = re.compile(r"expect:\s*((?:[A-Z]+-[A-Z0-9]+-\d+)(?:\s*,\s*[A-Z]+-[A-Z0-9]+-\d+)*)")
EXPECT_NONE_RE = re.compile(r"expect-none:\s*((?:[A-Z]+-[A-Z0-9]+-\d+)(?:\s*,\s*[A-Z]+-[A-Z0-9]+-\d+)*)")


@dataclass
class RuleScore:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    samples: List[str] = field(default_factory=list)

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else 1.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else 1.0


def _annotations(text: str) -> Tuple[Set[Tuple[int, str]], Set[str]]:
    expected: Set[Tuple[int, str]] = set()
    forbidden: Set[str] = set()
    for number, line in enumerate(text.splitlines(), 1):
        for match in EXPECT_RE.finditer(line):
            for rule_id in re.split(r"\s*,\s*", match.group(1)):
                expected.add((number, rule_id))
        for match in EXPECT_NONE_RE.finditer(line):
            forbidden.update(re.split(r"\s*,\s*", match.group(1)))
    return expected, forbidden


def case_files(extra_dirs: Optional[List[str]] = None) -> List[str]:
    files = []
    for directory in [CORPUS_DIR] + list(extra_dirs or []):
        if not os.path.isdir(directory):
            continue
        for current, _dirs, names in os.walk(directory):
            for name in sorted(names):
                if not name.startswith(".") and not name.endswith((".pyc", ".md")):
                    files.append(os.path.join(current, name))
    return files


def run(extra_dirs: Optional[List[str]] = None, rule_filter: str = "", semantic: bool = True) -> Dict:
    scanner = Scanner(ScanOptions(offline=True, learning=False, semantic=semantic), EventBus())
    scores: Dict[str, RuleScore] = {}
    cases = []
    for path in case_files(extra_dirs):
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            text = handle.read()
        expected, forbidden = _annotations(text)
        rel = os.path.basename(path)
        info = FileInfo(rel=rel, abs=path, size=len(text), language=detect_language(rel))
        scanner.findings = []
        found = {(f.line, f.rule_id) for f in scanner.analyze_text(info, text)}
        relevant = {rule for _line, rule in expected} | forbidden
        tp = expected & found
        fn = expected - found
        fp = {(line, rule) for line, rule in found - expected if rule in relevant}
        for line, rule in tp:
            scores.setdefault(rule, RuleScore()).tp += 1
        for line, rule in fn:
            score = scores.setdefault(rule, RuleScore())
            score.fn += 1
            score.samples.append(f"missed {rel}:{line}")
        for line, rule in fp:
            score = scores.setdefault(rule, RuleScore())
            score.fp += 1
            score.samples.append(f"false positive {rel}:{line}")
        cases.append({"file": rel, "tp": len(tp), "fp": len(fp), "fn": len(fn)})
    if rule_filter:
        scores = {k: v for k, v in scores.items() if rule_filter.lower() in k.lower()}
    total_tp = sum(s.tp for s in scores.values())
    total_fp = sum(s.fp for s in scores.values())
    total_fn = sum(s.fn for s in scores.values())
    return {
        "cases": cases,
        "rules": {rule: {"tp": s.tp, "fp": s.fp, "fn": s.fn, "precision": round(s.precision, 3),
                         "recall": round(s.recall, 3), "samples": s.samples[:10]} for rule, s in sorted(scores.items())},
        "precision": round(total_tp / (total_tp + total_fp), 3) if total_tp + total_fp else 1.0,
        "recall": round(total_tp / (total_tp + total_fn), 3) if total_tp + total_fn else 1.0,
        "tp": total_tp, "fp": total_fp, "fn": total_fn,
    }
