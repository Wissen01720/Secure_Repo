"""Benchmark against third-party repositories that were not written for Secure Repo.

The built-in corpus is written by the rule authors, so its 100 % says little. This benchmark audits real, public
projects pinned to an exact commit:

* **vulnerable-by-design applications** (NodeGoat, DVPWA, Vulnerable-Flask-App): a list of weaknesses that really exist
  in their code ("known") measures *recall*;
* a **clean, mature library** (requests) measures false positives;
* every finding Secure Repo reports is reviewed by hand and recorded as a true or false positive ("verdicts"), which
  measures *precision*. A finding without a verdict makes the benchmark fail, so the labels cannot silently rot.

The manifests (``external/*.toml``) are plain data: the reviewer's verdicts are visible and can be disputed.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from secure_repo.core.events import EventBus
from secure_repo.core.scanner import Scanner, ScanOptions
from secure_repo.core.workspace import Target

try:  # Python 3.11+
    import tomllib as _toml
except ModuleNotFoundError:  # pragma: no cover
    import tomli as _toml  # type: ignore

EXTERNAL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "extdata")
LINE_TOLERANCE = 6


@dataclass
class Known:
    id: str
    title: str
    file: str
    rules: List[str]
    cwe: str = ""
    line: int = 0


@dataclass
class Verdict:
    rule: str
    file: str
    verdict: str            # "TP" | "FP"
    note: str = ""
    line: int = 0           # 0 = every occurrence of the rule in that file


@dataclass
class Manifest:
    name: str
    repo: str
    commit: str
    kind: str               # "vulnerable" | "clean"
    language: str
    description: str = ""
    known: List[Known] = field(default_factory=list)
    verdicts: List[Verdict] = field(default_factory=list)


@dataclass
class RepoResult:
    manifest: Manifest
    tp: int = 0
    fp: int = 0
    tp_confident: int = 0       # findings of medium or high confidence
    fp_confident: int = 0
    tp_production: int = 0      # findings outside test code
    fp_production: int = 0
    unlabeled: List[str] = field(default_factory=list)
    found: List[str] = field(default_factory=list)
    missed: List[str] = field(default_factory=list)
    seconds: float = 0.0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else 1.0

    @property
    def precision_confident(self) -> float:
        total = self.tp_confident + self.fp_confident
        return self.tp_confident / total if total else 1.0

    @property
    def precision_production(self) -> float:
        total = self.tp_production + self.fp_production
        return self.tp_production / total if total else 1.0

    @property
    def recall(self) -> Optional[float]:
        total = len(self.found) + len(self.missed)
        return len(self.found) / total if total else None


def load_manifests(directory: str = EXTERNAL_DIR) -> List[Manifest]:
    manifests = []
    for name in sorted(os.listdir(directory)):
        if not name.endswith(".toml"):
            continue
        with open(os.path.join(directory, name), "rb") as handle:
            data = _toml.load(handle)
        manifest = Manifest(
            name=data["name"], repo=data["repo"], commit=data["commit"], kind=data["kind"],
            language=data.get("language", ""), description=data.get("description", ""),
            known=[Known(id=k["id"], title=k["title"], file=k["file"], rules=list(k.get("rules", [])),
                         cwe=k.get("cwe", ""), line=int(k.get("line", 0))) for k in data.get("known", [])],
            verdicts=[Verdict(rule=v["rule"], file=v["file"], verdict=v["verdict"], note=v.get("note", ""),
                              line=int(v.get("line", 0))) for v in data.get("verdict", [])])
        if manifest.kind not in ("vulnerable", "clean"):
            raise ValueError(f"{name}: kind must be 'vulnerable' or 'clean'")
        for verdict in manifest.verdicts:
            if verdict.verdict not in ("TP", "FP"):
                raise ValueError(f"{name}: verdict must be TP or FP ({verdict.rule} {verdict.file})")
        manifests.append(manifest)
    return manifests


def _git(args: List[str], cwd: str) -> None:
    subprocess.run(["git"] + args, cwd=cwd, check=True, capture_output=True, text=True, timeout=600)


def fetch(manifest: Manifest, cache_dir: str) -> str:
    """Check out the pinned commit of the repository (shallow) and return its path."""
    path = os.path.join(cache_dir, manifest.name)
    marker = os.path.join(path, ".sr-benchmark-commit")
    if os.path.isfile(marker):
        with open(marker, encoding="utf-8") as handle:
            if handle.read().strip() == manifest.commit:
                return path
    os.makedirs(path, exist_ok=True)
    if not os.path.isdir(os.path.join(path, ".git")):
        _git(["init", "-q"], path)
        _git(["remote", "add", "origin", manifest.repo], path)
    _git(["fetch", "-q", "--depth", "1", "origin", manifest.commit], path)
    _git(["checkout", "-q", "--force", manifest.commit], path)
    with open(marker, "w", encoding="utf-8") as handle:
        handle.write(manifest.commit + "\n")
    return path


def _verdict_for(manifest: Manifest, finding: Dict) -> Optional[Verdict]:
    exact = [v for v in manifest.verdicts if v.rule == finding["rule_id"] and v.file == finding["file"]]
    for verdict in exact:
        if verdict.line and verdict.line == finding["line"]:
            return verdict
    for verdict in exact:
        if not verdict.line:
            return verdict
    return None


def reportable(finding: Dict) -> bool:
    """Findings that a reviewer is asked to judge: code, secrets and dependencies - not repository hygiene facts."""
    return finding["status"] == "open" and finding["source"] != "hygiene" and finding["severity"] != "info"


def evaluate(manifest: Manifest, path: str) -> RepoResult:
    import time

    started = time.time()
    options = ScanOptions(offline=True, trust_repo_config=False, learning=False, resolve_versions=False)
    report, _ = Scanner(options, EventBus()).run(Target.parse(path), write_reports=False)
    result = RepoResult(manifest=manifest, seconds=round(time.time() - started, 1))
    findings = [f for f in report["findings"] if reportable(f)]
    seen: set = set()
    for finding in findings:
        key = (finding["rule_id"], finding["file"], finding["line"])
        if key in seen:
            continue
        seen.add(key)
        verdict = _verdict_for(manifest, finding)
        if verdict is None:
            result.unlabeled.append(f"{finding['rule_id']} {finding['file']}:{finding['line']}")
            continue
        confident = finding["confidence"] in ("medium", "high")
        production = not finding.get("in_test")
        if verdict.verdict == "TP":
            result.tp += 1
            result.tp_confident += int(confident)
            result.tp_production += int(production)
        else:
            result.fp += 1
            result.fp_confident += int(confident)
            result.fp_production += int(production)
    for known in manifest.known:
        hit = any(f["rule_id"] in known.rules and f["file"] == known.file
                  and (not known.line or abs(f["line"] - known.line) <= LINE_TOLERANCE) for f in findings)
        (result.found if hit else result.missed).append(f"{known.id} {known.title} ({known.file})")
    return result


def run(cache_dir: str, names: Optional[List[str]] = None, directory: str = EXTERNAL_DIR,
        download: bool = False) -> List[RepoResult]:
    results = []
    for manifest in load_manifests(directory):
        if names and manifest.name not in names:
            continue
        path = fetch(manifest, cache_dir) if download else os.path.join(cache_dir, manifest.name)
        if not os.path.isdir(path):
            raise FileNotFoundError(f"{manifest.name}: not found in {cache_dir} (run with --fetch to download it)")
        results.append(evaluate(manifest, path))
    return results


def totals(results: List[RepoResult]) -> Dict[str, object]:
    tp = sum(r.tp for r in results)
    fp = sum(r.fp for r in results)
    tp_c = sum(r.tp_confident for r in results)
    fp_c = sum(r.fp_confident for r in results)
    tp_p = sum(r.tp_production for r in results)
    fp_p = sum(r.fp_production for r in results)
    found = sum(len(r.found) for r in results)
    missed = sum(len(r.missed) for r in results)
    return {
        "repositories": len(results), "tp": tp, "fp": fp, "precision": tp / (tp + fp) if tp + fp else 1.0,
        "tp_confident": tp_c, "fp_confident": fp_c, "tp_production": tp_p, "fp_production": fp_p,
        "precision_production": tp_p / (tp_p + fp_p) if tp_p + fp_p else 1.0,
        "precision_confident": tp_c / (tp_c + fp_c) if tp_c + fp_c else 1.0,
        "known": found + missed, "found": found, "recall": found / (found + missed) if found + missed else 1.0,
        "unlabeled": sum(len(r.unlabeled) for r in results),
    }


def by_language(results: List[RepoResult]) -> List[Tuple[str, Dict[str, object]]]:
    groups: Dict[str, List[RepoResult]] = {}
    for result in results:
        groups.setdefault(result.manifest.language or "other", []).append(result)
    return [(language, totals(group)) for language, group in sorted(groups.items())]
