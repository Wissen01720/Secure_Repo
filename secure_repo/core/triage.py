"""Triage knowledge base: the feedback loop that makes the analysis better over time.

Every finding gets a *fingerprint* that survives line shifts (rule + file + normalized code).
Analysts mark findings as ``confirmed``, ``accepted_risk`` or ``false_positive``; decisions are
stored locally and re-applied on every scan. False positives can also be generalized to a
*learned pattern* (the code "shape" with literals abstracted) for one project or globally,
and per-rule statistics feed the confidence model: rules that keep producing false positives
in your code base are automatically demoted, rules that are always confirmed are promoted.

Data lives in the user's application-data folder (never inside the audited repository unless
explicitly exported with ``secure-repo triage export --to-repo``).
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import tempfile
import threading
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from secure_repo.core.models import TRIAGE_STATUSES

REPO_TRIAGE_FILE = os.path.join(".securerepo", "triage.json")
_LOCK = threading.Lock()


def data_dir() -> str:
    override = os.environ.get("SECURE_REPO_HOME")
    if override:
        base = override
    elif platform.system() == "Windows":
        base = os.path.join(os.environ.get("APPDATA") or os.path.expanduser("~"), "SecureRepo")
    elif platform.system() == "Darwin":
        base = os.path.join(os.path.expanduser("~"), "Library", "Application Support", "SecureRepo")
    else:
        base = os.path.join(os.environ.get("XDG_DATA_HOME") or os.path.join(os.path.expanduser("~"), ".local", "share"),
                            "secure-repo")
    os.makedirs(base, exist_ok=True)
    return base


def default_output_dir() -> str:
    """Reports live next to the triage data, never inside the repository being audited."""
    return os.path.join(data_dir(), "reports")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------------- identity
_STRING_RE = re.compile(r"""(?:[rbuf]{0,2})("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`)""")
_NUMBER_RE = re.compile(r"\b\d+(?:\.\d+)?\b")


def normalize_code(snippet: str) -> str:
    return re.sub(r"\s+", " ", (snippet or "").strip())


def code_shape(snippet: str) -> str:
    """Abstract literals so structurally identical lines share a shape."""
    text = _STRING_RE.sub("STR", snippet or "")
    text = _NUMBER_RE.sub("NUM", text)
    return re.sub(r"\s+", " ", text.strip())[:300]


def fingerprint(finding: Dict) -> str:
    extra = finding.get("extra") or {}
    if finding.get("source") == "dependency" and extra.get("package"):
        basis = f"{finding['rule_id']}|dep|{extra.get('ecosystem')}|{extra.get('package')}|{extra.get('version', '')}"
    elif finding.get("file") in ("", "."):
        basis = f"{finding['rule_id']}|repo"
    else:
        basis = f"{finding['rule_id']}|{finding.get('file')}|{normalize_code(finding.get('snippet', ''))}"
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:20]


def project_key(meta: Dict) -> Tuple[str, str]:
    """Stable project identity: remote URL when known (shared by clones), else the local path."""
    remote = (meta.get("remote") or "").strip()
    if not remote and meta.get("target_kind") == "remote":
        remote = meta.get("target", "")
    if remote:
        cleaned = re.sub(r"^[a-z+]+://([^@/]+@)?", "", remote.lower())
        cleaned = re.sub(r"^git@", "", cleaned).replace(":", "/")
        cleaned = re.sub(r"\.git$", "", cleaned.rstrip("/"))
        return "remote:" + cleaned, meta.get("name", cleaned)
    path = os.path.normcase(os.path.abspath(meta.get("target", ".")))
    return "path:" + path, meta.get("name", os.path.basename(path))


# ---------------------------------------------------------------------- knowledge base
class KnowledgeBase:
    def __init__(self, path: Optional[str] = None):
        self.path = path or os.path.join(data_dir(), "knowledge.json")
        self.data = {"version": 1, "projects": {}, "patterns": [], "rule_stats": {}}
        self.load()

    # persistence --------------------------------------------------------------
    def load(self) -> None:
        if os.path.isfile(self.path):
            try:
                with open(self.path, encoding="utf-8") as handle:
                    loaded = json.load(handle)
                if isinstance(loaded, dict):
                    self.data.update({k: loaded.get(k, v) for k, v in self.data.items()})
            except (OSError, ValueError):
                pass

    def save(self) -> None:
        with _LOCK:
            directory = os.path.dirname(self.path)
            os.makedirs(directory, exist_ok=True)
            handle, temp = tempfile.mkstemp(dir=directory, prefix=".knowledge-", suffix=".json")
            with os.fdopen(handle, "w", encoding="utf-8") as out:
                json.dump(self.data, out, indent=2, ensure_ascii=False)
            os.replace(temp, self.path)

    # decisions ------------------------------------------------------------------
    def project(self, key: str, name: str = "") -> Dict:
        projects = self.data["projects"]
        if key not in projects:
            projects[key] = {"name": name or key, "decisions": {}}
        elif name:
            projects[key]["name"] = name
        return projects[key]

    def record(self, key: str, name: str, finding: Dict, status: str, reason: str = "", scope: str = "finding",
               author: str = "") -> Dict:
        if status not in TRIAGE_STATUSES:
            raise ValueError(f"Unknown status {status!r}. Use one of: {', '.join(TRIAGE_STATUSES)}")
        fp = finding.get("fingerprint") or fingerprint(finding)
        decisions = self.project(key, name)["decisions"]
        previous = decisions.get(fp, {}).get("status")
        stats = self.data["rule_stats"].setdefault(finding["rule_id"], {})
        if previous and previous != "open":
            stats[previous] = max(0, stats.get(previous, 0) - 1)
        if status == "open":
            decisions.pop(fp, None)
        else:
            decisions[fp] = {"status": status, "reason": reason, "rule_id": finding["rule_id"],
                             "file": finding.get("file"), "line": finding.get("line"),
                             "snippet": (finding.get("snippet") or "")[:300], "author": author, "date": _now(),
                             "scope": scope}
            stats[status] = stats.get(status, 0) + 1
        if status == "false_positive" and scope in ("project-pattern", "global-pattern"):
            shape = code_shape(finding.get("snippet", ""))
            if shape:
                self.data["patterns"].append({
                    "id": uuid.uuid4().hex[:10], "rule_id": finding["rule_id"], "shape": shape,
                    "project": key if scope == "project-pattern" else None, "reason": reason, "author": author,
                    "date": _now(), "example_file": finding.get("file"),
                })
        self.save()
        return {"fingerprint": fp, "status": status}

    def forget(self, identifier: str) -> bool:
        removed = False
        for project in self.data["projects"].values():
            if identifier in project["decisions"]:
                del project["decisions"][identifier]
                removed = True
        before = len(self.data["patterns"])
        self.data["patterns"] = [p for p in self.data["patterns"] if p["id"] != identifier]
        removed = removed or len(self.data["patterns"]) != before
        if removed:
            self.save()
        return removed

    def reset(self) -> None:
        self.data = {"version": 1, "projects": {}, "patterns": [], "rule_stats": {}}
        self.save()

    # learning ---------------------------------------------------------------------
    def rule_quality(self, rule_id: str) -> Tuple[int, float]:
        """Return (feedback count, false-positive ratio) for a rule."""
        stats = self.data["rule_stats"].get(rule_id, {})
        false_positive = stats.get("false_positive", 0)
        positive = stats.get("confirmed", 0) + stats.get("accepted_risk", 0)
        total = false_positive + positive
        return total, (false_positive / total if total else 0.0)

    def stats(self) -> List[Dict]:
        rows = []
        for rule_id, stats in sorted(self.data["rule_stats"].items()):
            total, ratio = self.rule_quality(rule_id)
            if not total:
                continue
            rows.append({"rule_id": rule_id, "confirmed": stats.get("confirmed", 0),
                         "accepted_risk": stats.get("accepted_risk", 0),
                         "false_positive": stats.get("false_positive", 0), "feedback": total,
                         "precision": round(1 - ratio, 2),
                         "patterns": sum(1 for p in self.data["patterns"] if p["rule_id"] == rule_id)})
        return rows

    def apply(self, findings: List[Dict], key: str, repo_payload: Optional[Dict] = None) -> Dict[str, int]:
        """Apply stored decisions and learned patterns to a list of finding dicts."""
        counts = {"decisions": 0, "learned_patterns": 0, "repo_decisions": 0, "repo_patterns": 0}
        repo_payload = repo_payload or {}
        own = self.data["projects"].get(key, {}).get("decisions", {})
        repo_decisions = {fp: d for fp, d in (repo_payload.get("decisions") or {}).items() if isinstance(d, dict)}
        decisions = dict(repo_decisions)
        decisions.update(own)  # the analyst's own decision always wins over the repository's
        patterns = [dict(p, _repo=False) for p in self.data["patterns"] if p.get("project") in (None, key)]
        patterns += [dict(p, _repo=True) for p in repo_payload.get("patterns") or []
                     if isinstance(p, dict) and p.get("shape") and p.get("rule_id")]
        for finding in findings:
            if finding.get("status", "open") != "open":
                continue  # already suppressed (inline comment, disabled rule...): keep the original reason
            fp = finding["fingerprint"]
            decision = decisions.get(fp)
            if decision:
                from_repo = fp in repo_decisions and fp not in own
                finding["status"] = decision["status"]
                finding["triage"] = {"reason": decision.get("reason", ""), "author": decision.get("author", ""),
                                     "date": decision.get("date", ""),
                                     "origin": "repo-decision" if from_repo else "decision"}
                counts["repo_decisions" if from_repo else "decisions"] += 1
                continue
            if finding.get("source") in ("dependency", "hygiene"):
                continue
            shape = code_shape(finding.get("snippet", ""))
            for pattern in patterns:
                if pattern["rule_id"] == finding["rule_id"] and pattern["shape"] == shape:
                    finding["status"] = "false_positive"
                    finding["triage"] = {"reason": pattern.get("reason") or "Matches a learned false-positive pattern",
                                         "author": pattern.get("author", ""), "date": pattern.get("date", ""),
                                         "origin": "repo-pattern" if pattern["_repo"] else "learned-pattern",
                                         "pattern": pattern.get("id", "")}
                    counts["repo_patterns" if pattern["_repo"] else "learned_patterns"] += 1
                    break
        return counts

    # sharing ----------------------------------------------------------------------
    def export(self, path: str, key: Optional[str] = None) -> int:
        payload = {"version": 1, "exported": _now(), "patterns": self.data["patterns"],
                   "rule_stats": self.data["rule_stats"], "projects": self.data["projects"]}
        if key is not None:
            payload = {"version": 1, "exported": _now(),
                       "decisions": self.data["projects"].get(key, {}).get("decisions", {}),
                       "patterns": [p for p in self.data["patterns"] if p.get("project") in (None, key)]}
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, ensure_ascii=False)
        return len(payload.get("decisions", {})) + len(payload.get("patterns", []))

    def import_file(self, path: str, key: Optional[str] = None) -> int:
        with open(path, encoding="utf-8") as handle:
            payload = json.load(handle)
        imported = 0
        known = {p["id"] for p in self.data["patterns"]}
        for pattern in payload.get("patterns", []):
            if pattern.get("id") not in known:
                self.data["patterns"].append(pattern)
                imported += 1
        if "decisions" in payload and key:
            self.project(key)["decisions"].update(payload["decisions"])
            imported += len(payload["decisions"])
        for project_key_, project in (payload.get("projects") or {}).items():
            self.project(project_key_, project.get("name", ""))["decisions"].update(project.get("decisions", {}))
            imported += len(project.get("decisions", {}))
        for rule_id, stats in (payload.get("rule_stats") or {}).items():
            target = self.data["rule_stats"].setdefault(rule_id, {})
            for status, value in stats.items():
                target[status] = max(target.get(status, 0), value)
        self.save()
        return imported

    def export_cases(self, directory: str) -> int:
        """Turn false-positive decisions into benchmark regression cases (code snippets only)."""
        comment = {".py": "#", ".rb": "#", ".sh": "#", ".yml": "#", ".yaml": "#", ".tf": "#", ".php": "//",
                   ".js": "//", ".ts": "//", ".java": "//", ".go": "//", ".cs": "//", ".c": "//", ".cpp": "//",
                   ".kt": "//", ".rs": "//", ".swift": "//"}
        os.makedirs(directory, exist_ok=True)
        written = 0
        for project in self.data["projects"].values():
            for fp, decision in project["decisions"].items():
                if decision["status"] != "false_positive" or not decision.get("snippet"):
                    continue
                ext = os.path.splitext(decision.get("file") or "")[1].lower()
                if ext not in comment:
                    continue
                name = f"fp_{decision['rule_id'].lower().replace('-', '_')}_{fp[:8]}{ext}"
                with open(os.path.join(directory, name), "w", encoding="utf-8") as handle:
                    handle.write(f"{comment[ext]} securerepo-benchmark: false positive reported by triage\n")
                    handle.write(f"{comment[ext]} expect-none: {decision['rule_id']}\n")
                    handle.write(decision["snippet"] + "\n")
                written += 1
        return written


def load_repo_triage(root: str) -> Dict:
    """Team-shared decisions and patterns committed in the audited repository (.securerepo/triage.json)."""
    path = os.path.join(root, REPO_TRIAGE_FILE)
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, encoding="utf-8") as handle:
            payload = json.load(handle)
        return payload if isinstance(payload, dict) else {}
    except (OSError, ValueError):
        return {}
