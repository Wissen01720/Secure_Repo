"""State and small helpers shared by every scanner module (the mixins build on this class)."""

from __future__ import annotations

from datetime import datetime
from typing import Dict, List, Optional, Tuple

from secure_repo.core import netio, triage
from secure_repo.core.config import ProjectConfig
from secure_repo.core.events import EventBus
from secure_repo.core.models import Finding, owasp_key
from secure_repo.core.rules import PATTERN_RULES, Rule
from secure_repo.core.scan_common import ScanCancelled, ScanOptions


class ScannerBase:
    def __init__(self, options: ScanOptions, bus: Optional[EventBus] = None, knowledge: Optional[triage.KnowledgeBase] = None):
        self.options = options
        self.bus = bus or EventBus()
        self.findings: List[Finding] = []
        self.cancelled = False
        self.rules: List[Rule] = list(PATTERN_RULES)
        self.path_rules: List[Rule] = [r for r in self.rules if r.path]
        self.config = ProjectConfig()
        self.knowledge = knowledge if knowledge is not None else (triage.KnowledgeBase() if options.learning else None)
        self.noise: Dict[str, int] = {}
        self.trusted = False
        self.trust_reason = ""
        self.inline_ignored = 0                 # inline suppression comments NOT honoured (untrusted target)
        self.ignore_markers: List[str] = []     # files carrying a legacy "ignore-file" marker (never honoured)
        self._min_conf_from_repo = False
        # What was NOT (fully) analyzed - shown in every report so the analyst knows the blind spots.
        self.not_analyzed: Dict = {"directories": [], "minified": [], "too_large": [], "binary": 0, "by_type": 0,
                                   "unparsed": [], "intel": []}
        self.engine_stats: Dict[str, int] = {"python_ast": 0, "python_fallback": 0, "js_flow": 0, "masked_files": 0}
        self._rule_cache: Dict[Tuple[str, Tuple[str, ...]], List[Rule]] = {}
        self.log_lines: List[str] = []
        self.network = netio.NetworkSession()
        self.web_facts: List[Dict] = []         # per-file facts for checks that need the whole project (CSRF)
        self.bus.subscribe(self._collect_log)

    def _collect_log(self, event: Dict) -> None:
        stamp = datetime.fromtimestamp(event["ts"]).strftime("%Y-%m-%d %H:%M:%S")
        if event["type"] == "log":
            self.log_lines.append(f"{stamp} [{event['level'].upper():5}] {event['message']}")
        elif event["type"] == "stage":
            detail = f" - {event['detail']}" if event.get("detail") else ""
            self.log_lines.append(f"{stamp} [STAGE] {event['title']}: {event['status']}{detail}")
        elif event["type"] == "error":
            self.log_lines.append(f"{stamp} [ERROR] {event['message']}")

    # ------------------------------------------------------------------ helpers
    def _check_cancel(self) -> None:
        if self.cancelled:
            raise ScanCancelled("Scan cancelled by user")

    def _count_noise(self, reason: str, amount: int = 1) -> None:
        self.noise[reason] = self.noise.get(reason, 0) + amount

    def _add(self, finding: Finding) -> None:
        self.findings.append(finding)
        if finding.status != "open":
            return  # suppressed findings are kept for the audit trail but are not announced as live findings
        self.bus.emit("finding", rule_id=finding.rule_id, title=finding.title, severity=finding.severity,
                      file=finding.file, line=finding.line, category=finding.category)

    def _finding_from_rule(self, rule: Rule, info_rel: str, line: int, snippet: str = "", detail: str = "",
                           severity: Optional[str] = None, in_test: bool = False, title: Optional[str] = None,
                           extra: Optional[Dict] = None, engine: Optional[str] = None,
                           flow: Optional[List[Dict]] = None, confidence_label: Optional[str] = None) -> Finding:
        default_engine = {"dependency": "dependency", "hygiene": "hygiene"}.get(rule.source, "pattern")
        if rule.category == "Custom":
            default_engine = "custom"
        return Finding(rule_id=rule.id, title=title or rule.title, severity=severity or rule.severity,
                       category=rule.category, file=info_rel, line=line, snippet=snippet, detail=detail,
                       cwe=rule.cwe, owasp=owasp_key(rule.owasp), tags=list(rule.tags),
                       confidence=confidence_label or rule.confidence, source=rule.source, in_test=in_test,
                       extra=extra or {}, engine=engine or default_engine, flow=flow or [])
