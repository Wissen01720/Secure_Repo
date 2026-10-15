"""Scan orchestrator: runs every analysis stage and assembles the report.

Analysis layers applied to each source file:

1. **Lexical masking** - comments and string literals are blanked (offsets preserved) so code
   patterns never match inside comments, docstrings or messages.
2. **Semantic engines** - Python is parsed into a syntax tree with taint tracking; JavaScript /
   TypeScript get a data-flow pass that confirms, escalates or discards pattern findings.
3. **Patterns** - 160+ rules for every other language and for configuration/IaC/CI files.
4. **Confidence & learning** - each finding is scored and the triage knowledge base (decisions,
   learned false-positive patterns, per-rule statistics) plus the project configuration are applied.
"""

from __future__ import annotations

import bisect
import os
import pickle
import platform
import re
import time
import urllib.error
from concurrent.futures import ProcessPoolExecutor
from concurrent.futures.process import BrokenProcessPool
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from secure_repo import __author__, __version__
from secure_repo.core import (checks, compliance, confidence, deps as depmod, gitops, intel, jsflow, lexer, pyast,
                              regions, resolver, summary as summarymod, thirdparty, triage, webchecks)
from secure_repo.core.config import ProjectConfig, load_config
from secure_repo.core.events import EventBus
from secure_repo.core.languages import DOCUMENTATION
from secure_repo.core.models import OWASP_TOP10, SEVERITY_RANK, SUPPRESSED_STATUSES, Dependency, Finding, owasp_key
from secure_repo.core.rules import PATTERN_RULES, RULES, RULES_BY_ID, Rule, canonical_rule_id
from secure_repo.core.walker import FileInfo, StructureTree, enumerate_files, read_text
from secure_repo.core.workspace import Target, Workspace, prepare_workspace

# Inline suppression directives are only honoured inside real comments of trusted targets, and they are always
# recorded in the report (status "suppressed_inline"). Optionally followed by rule IDs: ``# nosec SR-PY-005 reason``.
TEST_SEVERITY_STEP = {"critical": "high", "high": "medium", "medium": "low"}
MARKUP_EXTENSIONS = (".html", ".htm", ".xhtml", ".ejs", ".hbs", ".handlebars", ".jinja", ".jinja2", ".j2", ".twig",
                    ".erb", ".cshtml", ".razor", ".vue", ".svelte", ".php", ".jsp", ".mustache", ".njk")
MAX_EVIDENCE_LINES = 6      # lines of a multi-line call shown as evidence
EVIDENCE_LIMIT = 320        # characters
DIRECTIVE_RE = re.compile(r"(?i)\bnosec\b|securerepo:ignore\b(?!-file)|noqa:\s*secure")
RULE_ID_RE = re.compile(r"\b[A-Z][A-Z0-9]*(?:-[A-Z][A-Z0-9]*)*-\d{1,4}\b")
COMMENT_START_RE = re.compile(r"#|//|--|<!--|/\*|\brem\b|::", re.IGNORECASE)
IGNORE_FILE_MARKER = "securerepo:ignore-file"
# Only these languages are ever minified in practice. A one-line .py/.php/.go file is NOT minified code: it is
# either hostile or generated, and must be analyzed in full.
MINIFIABLE_LANGUAGES = {"JavaScript", "TypeScript", "CSS"}
COMMENT_PREFIXES = ("#", "//", "/*", "* ", "*/", "--", "<!--", ";", "rem ", "REM ", "::")
MAX_PER_RULE_PER_FILE = 50


@dataclass
class ScanOptions:
    offline: bool = False
    compliance: bool = False
    frameworks: List[str] = field(default_factory=lambda: ["all"])
    max_file_size: int = 2 * 1024 * 1024
    exclude: List[str] = field(default_factory=list)
    include_tests: bool = True
    enrich: bool = True
    auditor: str = ""
    output_dir: str = field(default_factory=lambda: triage.default_output_dir())
    min_confidence: str = "low"
    learning: bool = True          # apply the triage knowledge base (decisions, learned patterns, rule stats)
    resolve_versions: bool = True  # virtual lockfile resolution for unpinned dependencies
    semantic: bool = True          # lexical masking + syntax tree + data flow (False = legacy pattern-only engine)
    # Does the audited repository's own configuration (.securerepo.toml, .securerepo/triage.json, nosec comments)
    # get authority over the result? None = automatic: only for the working tree of a local Git repository.
    trust_repo_config: Optional[bool] = None
    jobs: int = 0                  # worker processes for file analysis: 0 = automatic, 1 = single process
    parallel_threshold: int = 400  # below this many files a single process is faster than starting workers

    def to_dict(self) -> Dict:
        return asdict(self)


class ScanCancelled(Exception):
    pass


MAX_AUTO_JOBS = 8
_WORKER: Dict[str, Scanner] = {}


def _init_worker(options: ScanOptions, config: ProjectConfig, trusted: bool) -> None:
    """Runs once in every worker process: a private scanner configured like the parent's (no learning, no events)."""
    scanner = Scanner(replace(options, learning=False), EventBus(), knowledge=None)
    scanner.config, scanner.trusted = config, trusted
    scanner.rules = list(PATTERN_RULES) + config.custom_rules
    scanner.path_rules = [r for r in scanner.rules if r.path]
    _WORKER["scanner"] = scanner


def _worker_process(info: FileInfo) -> Dict:
    return _WORKER["scanner"]._process_file(info, collect=True)


class Scanner:
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
                                   "unparsed": []}
        self.engine_stats: Dict[str, int] = {"python_ast": 0, "python_fallback": 0, "js_flow": 0, "masked_files": 0}
        self._rule_cache: Dict[Tuple[str, Tuple[str, ...]], List[Rule]] = {}
        self.log_lines: List[str] = []
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

    def _rules_for(self, info: FileInfo) -> List[Rule]:
        path_signature = tuple(rule.id for rule in self.path_rules if rule.applies_to(info.language, info.rel))
        key = (info.language, path_signature)
        cached = self._rule_cache.get(key)
        if cached is None:
            cached = [rule for rule in self.rules if rule.applies_to(info.language, info.rel)]
            self._rule_cache[key] = cached
        return cached

    @staticmethod
    def _inside_string(line_text: str, column: int) -> bool:
        """True when ``column`` falls inside a single-line string literal."""
        quote = None
        index = 0
        while index < column and index < len(line_text):
            char = line_text[index]
            if quote:
                if char == "\\":
                    index += 1
                elif char == quote:
                    quote = None
            elif char in ("'", '"', "`"):
                quote = char
            elif char == "#" or line_text.startswith("//", index):
                return False
            index += 1
        return quote is not None

    @staticmethod
    def _snippet(line_text: str, column: int, limit: int = 220) -> str:
        stripped = line_text.strip()
        offset = len(line_text) - len(line_text.lstrip())
        column = max(0, column - offset)
        if len(stripped) > limit:
            start = max(0, column - 80)
            stripped = ("…" if start else "") + stripped[start:start + limit - 20] + "…"
        return checks.redact_text(stripped)

    # ------------------------------------------------------------------ analysis
    def analyze_text(self, info: FileInfo, text: str, minified: bool = False) -> List[Finding]:
        """Analyze one file with every applicable engine; returns (and registers) its findings.

        ``minified`` (JS/CSS bundles only) runs a reduced analysis: no syntax-aware engines, and only secrets and
        critical findings are kept, with low confidence.
        """
        newlines = [m.start() for m in re.finditer("\n", text)]
        lines = text.split("\n")

        def locate(offset: int) -> Tuple[int, str, int]:
            index = bisect.bisect_right(newlines, offset - 1) if offset else 0
            line_start = newlines[index - 1] + 1 if index > 0 else 0
            return index + 1, lines[index] if index < len(lines) else "", offset - line_start

        def line_text_of(line_no: int) -> str:
            return lines[line_no - 1] if 0 < line_no <= len(lines) else ""

        comment_cache: Dict[int, str] = {}
        masked_lines: List[str] = []

        def comment_of(line_no: int) -> str:
            """Text of the real comment on a line (strings and code are excluded)."""
            if line_no in comment_cache:
                return comment_cache[line_no]
            original = line_text_of(line_no)
            comment = ""
            if original:
                if views is not None:
                    if not masked_lines:
                        masked_lines.extend(views["no_comments"].split("\n"))
                    masked = masked_lines[line_no - 1] if line_no - 1 < len(masked_lines) else original
                    changed = [i for i, (o, m) in enumerate(zip(original, masked)) if o != m]
                    comment = original[changed[0]:changed[-1] + 1] if changed else ""
                else:
                    start = COMMENT_START_RE.search(original)
                    comment = original[start.start():] if start else ""
            comment_cache[line_no] = comment
            return comment

        def inline_suppression(line_no: int, rule_id: str) -> Optional[Dict]:
            comment = comment_of(line_no)
            directive = DIRECTIVE_RE.search(comment) if comment else None
            if not directive:
                return None
            rule_ids = [canonical_rule_id(r) for r in RULE_ID_RE.findall(comment[directive.end():])]
            if rule_ids and rule_id not in rule_ids:
                return None
            if not self.trusted:
                self.inline_ignored += 1
                return None
            return {"reason": re.sub(r"\s+", " ", comment).strip()[:200], "rule_ids": rule_ids}

        in_test = info.in_test
        is_doc = info.language in DOCUMENTATION
        views = None if is_doc or minified or not self.options.semantic else lexer.mask(text, info.language)
        if views is not None:
            self.engine_stats["masked_files"] += 1
        lower = text.lower()
        file_findings: List[Finding] = []
        secret_lines = set()

        # Layer 2a - Python syntax tree + taint -------------------------------------
        python_semantic = False
        if info.language == "Python" and self.options.semantic:
            try:
                py_findings, suppressed = pyast.analyze_python(text, info.rel)
                python_semantic = True
                self.engine_stats["python_ast"] += 1
                for reason, amount in suppressed.items():
                    self._count_noise(f"python: {reason}", amount)
                for item in py_findings:
                    rule = RULES_BY_ID[item.rule_id]
                    first = self._snippet(line_text_of(item.line), item.col)
                    evidence, extra = first, dict(item.extra)
                    if item.end_line > item.line:
                        # Multi-line call: show the whole expression, but keep the first line as the stable basis
                        # of the fingerprint so earlier triage decisions still match.
                        last = min(item.end_line, item.line + MAX_EVIDENCE_LINES - 1)
                        joined = " ".join(line_text_of(n).strip() for n in range(item.line, last + 1))
                        evidence = self._snippet(re.sub(r"\s+", " ", joined), 0, limit=EVIDENCE_LIMIT)
                        if last < item.end_line:
                            evidence += " ..."
                        extra["fp_snippet"] = first
                    file_findings.append(self._finding_from_rule(
                        rule, info.rel, item.line, evidence, extra=extra,
                        detail=item.detail, severity=item.severity, in_test=in_test, title=item.title,
                        engine=item.engine, flow=item.flow, confidence_label=item.confidence))
            except (SyntaxError, ValueError, RecursionError, MemoryError):
                self.engine_stats["python_fallback"] += 1

        # Layer 3 - patterns on the right lexical view ------------------------------------------
        for rule in self._rules_for(info):
            if python_semantic and rule.id in pyast.OWNED_RULES:
                continue
            if rule.keywords and not any(keyword in lower for keyword in rule.keywords):
                continue
            if rule.skip_in_tests and in_test:
                self._count_noise(f"{rule.id}: rule not applied to test code")
                continue
            regex = rule.regex
            if regex is None:
                continue
            if views is None or rule.view == "raw":
                subject, engine = text, "pattern"
            else:
                subject, engine = (views["code"] if rule.view == "code" else views["no_comments"]), "lexical"
            if rule.category == "Custom":
                engine = "custom"
            seen = set()
            allowed_lines = None
            for match in regex.finditer(subject):
                line_no, _masked_line, column = locate(match.start())
                line_text = line_text_of(line_no)
                if line_no in seen:
                    continue
                if rule.region:
                    if allowed_lines is None:
                        allowed_lines = regions.REGIONS[rule.region](text)
                    if line_no not in allowed_lines:
                        self._count_noise(f"{rule.id}: outside {rule.region} (not an execution context)")
                        continue
                if views is None and not rule.scan_comments and line_text.lstrip().startswith(COMMENT_PREFIXES):
                    continue
                if rule.exclude_re and rule.exclude_re.search(line_text):
                    continue
                if views is not None and rule.view == "strings" and rule.source == "code" \
                        and self._inside_string(line_text, column):
                    end = column + max(len(match.group(0).split("\n", 1)[0]) - 1, 0)
                    if self._inside_string(line_text, end):
                        self._count_noise("match entirely inside a string literal")
                        continue
                if is_doc and rule.source == "code":
                    continue  # code patterns inside documentation are examples, not code
                if rule.id == "SR-SEC-018" and match.groups() and checks.is_placeholder_value(match.group(1)):
                    self._count_noise("credentials in URL: placeholder password")
                    continue
                seen.add(line_no)
                severity = rule.severity
                if is_doc and rule.source == "secret" and SEVERITY_RANK[severity] < SEVERITY_RANK["medium"]:
                    severity = "medium"
                if rule.source == "secret":
                    secret_lines.add(line_no)
                file_findings.append(self._finding_from_rule(rule, info.rel, line_no, self._snippet(line_text, column),
                                                             severity=severity, in_test=in_test, engine=engine))
                if len(seen) >= MAX_PER_RULE_PER_FILE:
                    break

        # Layer 2c - absent or weak settings that no single line shows (cookie flags) ----------------
        if views is not None and info.language in lexer.JS_LIKE and ("session" in lower or "cookie" in lower):
            for offset, detail in webchecks.cookie_flag_issues(views["no_comments"]):
                line_no, _masked, column = locate(offset)
                file_findings.append(self._finding_from_rule(
                    RULES_BY_ID[webchecks.RULE_COOKIE_FLAGS], info.rel, line_no,
                    self._snippet(line_text_of(line_no), column), detail=detail, in_test=in_test, engine="lexical"))

        # Layer 2b - JavaScript / TypeScript data flow --------------------------------------------
        if views is not None and info.language in lexer.JS_LIKE:
            self.engine_stats["js_flow"] += 1
            decisions, suppressed = jsflow.analyze_js(text, views["code"])
            for reason, amount in suppressed.items():
                self._count_noise(f"javascript: {reason}", amount)
            by_key: Dict[Tuple[str, int], jsflow.Decision] = {}
            for decision in decisions:
                current = by_key.get((decision.rule_id, decision.line))
                if current is None or decision.kind == "tainted":
                    by_key[(decision.rule_id, decision.line)] = decision
            kept: List[Finding] = []
            covered = set()
            for finding in file_findings:
                decision = by_key.get((finding.rule_id, finding.line))
                if finding.rule_id not in jsflow.HANDLED_RULES or decision is None:
                    kept.append(finding)
                    continue
                covered.add((finding.rule_id, finding.line))
                if decision.kind == "constant":
                    self._count_noise("javascript: constant or superseded sink")
                    continue
                if decision.kind == "tainted":
                    finding.severity = decision.severity or finding.severity
                    finding.engine, finding.flow, finding.detail = "taint", decision.flow, decision.detail
                    finding.confidence = "high"
                kept.append(finding)
            for (rule_id, line_no), decision in by_key.items():
                if decision.kind != "tainted" or (rule_id, line_no) in covered:
                    continue
                rule = RULES_BY_ID[rule_id]
                kept.append(self._finding_from_rule(rule, info.rel, line_no, self._snippet(line_text_of(line_no), 0),
                                                    detail=decision.detail, severity=decision.severity, in_test=in_test,
                                                    engine="taint", flow=decision.flow, confidence_label="high"))
            file_findings = kept

        # Secrets, personal data and Dockerfile semantics (always on the raw text) ------------------
        if info.language != "Other" or os.path.basename(info.rel).startswith("."):
            generic = RULES_BY_ID["SR-SEC-019"]
            for offset, key, value, entropy in checks.find_generic_credentials(text, info.language):
                line_no, line_text, column = locate(offset)
                if line_no in secret_lines:
                    continue
                secret_lines.add(line_no)
                severity = "high" if entropy >= 3.0 or len(value) >= 12 else "medium"
                if is_doc:
                    severity = "low"
                detail = (f"'{key}' is assigned a literal value ({len(value)} characters, entropy "
                          f"{entropy:.2f} bits/char). Value redacted: {checks.mask(value)}")
                file_findings.append(self._finding_from_rule(generic, info.rel, line_no, self._snippet(line_text, column),
                                                             detail=detail, severity=severity, in_test=in_test))

        if any(ch.isdigit() for ch in text[:200000]):
            card_rule = RULES_BY_ID["SR-PII-001"]
            for offset, number, is_test_card in checks.find_card_numbers(text):
                line_no, line_text, column = locate(offset)
                digits = re.sub(r"\D", "", number)
                detail = f"Card number {digits[:4]}********{digits[-2:]} passes the Luhn check."
                severity = card_rule.severity
                if is_test_card:
                    severity, detail = "info", detail + " It is a well-known test card number."
                file_findings.append(self._finding_from_rule(
                    card_rule, info.rel, line_no, self._snippet(line_text.replace(number, checks.mask(number)), column),
                    detail=detail, severity=severity, in_test=in_test))

        if info.language == "Dockerfile":
            for rule_id, line_no, snippet, detail in checks.analyze_dockerfile(text):
                file_findings.append(self._finding_from_rule(RULES_BY_ID[rule_id], info.rel, line_no, snippet,
                                                             detail=detail, in_test=in_test, engine="ast"))

        # Context that lowers confidence without hiding anything: bundled libraries and documentation examples.
        bundled = None if is_doc else thirdparty.detect(info.rel, info.language, text)
        example_lines = set()
        if info.rel.lower().endswith(MARKUP_EXTENSIONS) and ("<pre" in lower or "<code" in lower):
            example_lines = regions.markup_example_lines(text)
        for finding in file_findings:
            if finding.source in ("dependency", "hygiene"):
                continue
            if bundled:
                finding.extra["third_party"] = bundled
            if finding.line in example_lines:
                finding.extra["example_block"] = True

        if minified:
            kept_findings = []
            for finding in file_findings:
                if finding.source == "secret" or finding.severity == "critical":
                    finding.confidence = "low"
                    finding.extra["minified"] = True
                    kept_findings.append(finding)
                else:
                    self._count_noise("minified bundle: non-critical pattern match")
            file_findings = kept_findings

        for finding in file_findings:
            hit = inline_suppression(finding.line, finding.rule_id)
            if hit:
                note = "" if hit["rule_ids"] else " (no rule ID: this comment silences every rule on the line)"
                finding.status = "suppressed_inline"
                finding.triage = {"reason": hit["reason"] + note, "origin": "inline", "author": "", "date": "",
                                  "rule_ids": hit["rule_ids"]}
            self._add(finding)
        return file_findings

    # ------------------------------------------------------------------ stages
    def _process_file(self, info: FileInfo, collect: bool = False) -> Dict:
        """Everything that is done to one file, without touching the report-wide statistics.

        Runs in the main process (findings go straight to ``self.findings``) or in a worker process with
        ``collect=True`` (findings and counters are handed back to the parent, which merges them in file order).
        """
        findings_before = len(self.findings)
        noise_before, engines_before, inline_before = dict(self.noise), dict(self.engine_stats), self.inline_ignored
        outcome: Dict = {"rel": info.rel, "language": info.language, "size": info.size, "lines": None, "skip": None,
                         "minified": False, "marker": False, "scanned": False}
        sensitive = checks.match_sensitive_file(info.rel)
        text = None
        if info.scannable or sensitive:
            text = read_text(info, self.options.max_file_size)
        if sensitive:
            label, severity, required = sensitive
            if required is None or (text is not None and required.search(text)):
                rule = RULES_BY_ID["SR-SEC-020"]
                self._add(self._finding_from_rule(rule, info.rel, 0, info.rel, detail=label, severity=severity,
                                                  in_test=info.in_test))
        if text is None:
            outcome["skip"] = ("symlink" if info.is_symlink else
                               "too_large" if info.size > self.options.max_file_size else "binary")
        else:
            line_count = text.count("\n") + (0 if text.endswith("\n") or not text else 1)
            outcome["lines"] = line_count
            minified = (len(text) > 20000 and line_count < len(text) / 1500 and info.language in MINIFIABLE_LANGUAGES)
            outcome["marker"] = IGNORE_FILE_MARKER in text[:2000]
            if info.scannable and (self.options.include_tests or not info.in_test):
                outcome["minified"], outcome["scanned"] = minified, True
                self.analyze_text(info, text, minified=minified)
            else:
                outcome["skip"] = "filtered" if info.scannable else "by_type"
        if collect:
            outcome["findings"] = self.findings[findings_before:]
            del self.findings[findings_before:]
            outcome["noise"] = {k: v - noise_before.get(k, 0) for k, v in self.noise.items() if v != noise_before.get(k, 0)}
            outcome["engines"] = {k: v - engines_before.get(k, 0) for k, v in self.engine_stats.items()}
            outcome["inline_ignored"] = self.inline_ignored - inline_before
        return outcome

    def _worker_count(self, total: int) -> int:
        jobs = self.options.jobs
        if jobs <= 0:
            jobs = min(os.cpu_count() or 1, MAX_AUTO_JOBS)
        if jobs <= 1 or total < self.options.parallel_threshold:
            return 1
        return min(jobs, total)

    def _outcomes(self, files: List[FileInfo], workers: int):
        """Per-file outcomes in file order: from a pool of worker processes when it pays off, else in this process."""
        done = 0
        if workers > 1:
            pool = None
            try:
                pool = ProcessPoolExecutor(max_workers=workers, initializer=_init_worker,
                                           initargs=(self.options, self.config, self.trusted))
                self.bus.log(f"Analyzing {len(files)} files with {workers} worker processes", "ok")
                chunk = max(1, min(32, len(files) // (workers * 8)))
                for outcome in pool.map(_worker_process, files, chunksize=chunk):
                    self._merge_worker(outcome)
                    done += 1
                    yield outcome
                return
            except (BrokenProcessPool, OSError, ImportError, pickle.PicklingError) as exc:
                self.bus.log(f"Parallel analysis is unavailable ({type(exc).__name__}: {exc}); continuing in one process",
                             "warn")
            finally:
                if pool is not None:
                    pool.shutdown(wait=False, cancel_futures=True)
        for info in files[done:]:
            yield self._process_file(info)

    def _merge_worker(self, outcome: Dict) -> None:
        for finding in outcome.pop("findings", []):
            self._add(finding)
        for reason, amount in outcome.pop("noise", {}).items():
            self._count_noise(reason, amount)
        for engine, amount in outcome.pop("engines", {}).items():
            self.engine_stats[engine] = self.engine_stats.get(engine, 0) + amount
        self.inline_ignored += outcome.pop("inline_ignored", 0)

    def _stage_analyze(self, files: List[FileInfo], tree: StructureTree, stats: Dict) -> None:
        total = len(files)
        batch: List[str] = []
        last_emit = time.time()
        languages: Dict[str, Dict[str, int]] = {}
        for index, outcome in enumerate(self._outcomes(files, self._worker_count(total)), 1):
            self._check_cancel()
            skip = outcome["skip"]
            if skip in ("symlink", "too_large", "binary"):
                stats["skipped"] += 1
                if skip == "too_large" and len(self.not_analyzed["too_large"]) < 200:
                    self.not_analyzed["too_large"].append({"path": outcome["rel"], "bytes": outcome["size"]})
                elif skip == "binary":
                    self.not_analyzed["binary"] += 1
            else:
                tree.set_lines(outcome["rel"], outcome["lines"])
                lang = languages.setdefault(outcome["language"], {"files": 0, "lines": 0, "bytes": 0})
                lang["files"] += 1
                lang["lines"] += outcome["lines"]
                lang["bytes"] += outcome["size"]
                stats["lines"] += outcome["lines"]
                if outcome["marker"] and len(self.ignore_markers) < 200:
                    self.ignore_markers.append(outcome["rel"])  # reported, never honoured: use an explicit exclude instead
                if outcome["scanned"]:
                    if outcome["minified"] and len(self.not_analyzed["minified"]) < 200:
                        self.not_analyzed["minified"].append(outcome["rel"])
                    stats["scanned"] += 1
                else:
                    stats["skipped"] += 1
                    if skip == "by_type":
                        self.not_analyzed["by_type"] += 1
            batch.append(outcome["rel"])
            now = time.time()
            if now - last_emit > 0.12 or index == total:
                self.bus.emit("files", paths=batch, done=index, total=total)
                self.bus.progress("analyze", index, total, outcome["rel"])
                batch = []
                last_emit = now
        stats["languages"] = dict(sorted(languages.items(), key=lambda kv: -kv[1]["lines"]))

    def _stage_dependencies(self, files: List[FileInfo]) -> Tuple[List[Dependency], List[depmod.ParseIssue], List[str]]:
        manifests = [f for f in files if depmod.is_manifest(f.rel)]
        issues: List[depmod.ParseIssue] = []
        parsed: List[Tuple[Dependency, bool]] = []
        for index, info in enumerate(manifests, 1):
            self._check_cancel()
            parser, is_lock = depmod.parser_for(info.rel)
            text = read_text(info, 50 * 1024 * 1024)
            if text is None:
                continue
            problem = depmod.syntax_error(info.rel, text)
            if problem:
                # A damaged manifest must not look like "no dependencies": say so in the report.
                self.not_analyzed["unparsed"].append({"path": info.rel, "error": problem})
                self.bus.log(f"{info.rel} is not valid ({problem}); its dependencies may be missing", "warn")
            try:
                result = parser(text, info.rel, issues)
            except Exception as exc:  # malformed manifest - report and continue
                self.bus.log(f"Could not parse {info.rel}: {exc}", "warn")
                if not problem:
                    self.not_analyzed["unparsed"].append({"path": info.rel, "error": f"parser error: {str(exc)[:120]}"})
                continue
            for dep in result:
                if is_lock:
                    dep.direct = dep.direct and parser is depmod.parse_nuget_lock
                    dep.resolved_by = "lockfile"
                elif dep.version:
                    dep.resolved_by = "manifest"
                parsed.append((dep, is_lock))
            ecosystems = sorted({d.ecosystem for d in result}) or ["-"]
            self.bus.log(f"{info.rel} -> {len(result)} libraries ({', '.join(ecosystems)})", "ok")
            self.bus.progress("dependencies", index, len(manifests), info.rel)

        # A requirements file where every registry dependency is pinned (==) behaves like a lockfile.
        by_manifest: Dict[str, List[Dependency]] = {}
        for dep, _is_lock in parsed:
            by_manifest.setdefault(dep.manifest, []).append(dep)
        pinned_requirements = {
            manifest for manifest, items in by_manifest.items()
            if depmod.parser_for(manifest)[0] is depmod.parse_requirements
            and all(d.version for d in items if d.source == "registry")
        }

        # Link lockfile versions to direct declarations.
        lock_index: Dict[Tuple[str, str, str], List[str]] = {}
        lock_dirs: Dict[str, set] = {}
        for dep, is_lock in parsed:
            if is_lock or dep.manifest in pinned_requirements:
                directory = os.path.dirname(dep.manifest)
                lock_index.setdefault((dep.ecosystem, directory, depmod.normalize_name(dep.ecosystem, dep.name)), []).append(dep.version or "")
                lock_dirs.setdefault(dep.ecosystem, set()).add(directory)

        def ancestors(path: str) -> List[str]:
            chain, current = [], os.path.dirname(path)
            while True:
                chain.append(current)
                if not current:
                    return chain
                current = os.path.dirname(current)

        for dep, is_lock in parsed:
            if is_lock:
                continue
            for directory in ancestors(dep.manifest):
                if directory in lock_dirs.get(dep.ecosystem, set()):
                    dep.locked = True
                    versions = lock_index.get((dep.ecosystem, directory, depmod.normalize_name(dep.ecosystem, dep.name)))
                    if versions and not dep.version and dep.source == "registry":
                        dep.version = sorted(set(versions))[0]
                        dep.resolved_by = "lockfile"
                    break

        inventory: Dict[Tuple[str, str, str], Dependency] = {}
        for dep, _is_lock in sorted(parsed, key=lambda item: item[1]):
            identity = dep.version or f"spec:{dep.spec}"
            key = (dep.ecosystem, depmod.normalize_name(dep.ecosystem, dep.name), identity)
            existing = inventory.get(key)
            if existing is None:
                dep.manifests = [dep.manifest]
                inventory[key] = dep
            else:
                if dep.manifest not in existing.manifests:
                    existing.manifests.append(dep.manifest)
                existing.direct = existing.direct or dep.direct
                existing.locked = existing.locked or dep.locked
        return list(inventory.values()), issues, [m.rel for m in manifests]

    def _stage_resolve(self, inventory: List[Dependency], root: str) -> Dict[str, int]:
        counts = {"environment": 0, "registry": 0, "graph": 0}
        if not self.options.resolve_versions or not inventory:
            return counts
        counts["environment"] = resolver.resolve_from_environment(inventory, root)
        if counts["environment"]:
            self.bus.log(f"{counts['environment']} version(s) resolved from the installed environment", "ok")
        if not self.options.offline:
            try:
                counts["registry"] = resolver.resolve_from_registry(inventory, self.bus)
                added = resolver.resolve_graph(inventory, self.bus)
                inventory.extend(added)
                counts["graph"] = len(added)
            except (urllib.error.URLError, OSError, ValueError) as exc:
                self.bus.log(f"Registry resolution unavailable: {getattr(exc, 'reason', exc)}", "warn")
        return counts

    def _dependency_findings(self, inventory: List[Dependency], issues: List[depmod.ParseIssue]) -> None:
        unlocked: Dict[str, List[Dependency]] = {}
        for dep in inventory:
            if dep.direct and not dep.locked and dep.source == "registry" and dep.resolved_by not in ("manifest", "lockfile") \
                    and dep.ecosystem not in ("Go",) and dep.spec not in ("managed",):
                unlocked.setdefault(dep.manifest, []).append(dep)
            if dep.source in ("git", "url"):
                rule = RULES_BY_ID["SR-DEP-005"]
                self._add(self._finding_from_rule(rule, dep.manifest, dep.line, f"{dep.name} -> {checks.redact_text(dep.spec)}",
                                                  detail=f"{dep.name} is installed from {dep.source.upper()} source "
                                                         f"'{checks.redact_text(dep.spec)}'.",
                                                  extra={"package": dep.name, "ecosystem": dep.ecosystem}))
            bad = intel.known_bad(dep)
            if bad:
                rule = RULES_BY_ID[bad[0]]
                self._add(self._finding_from_rule(rule, dep.manifest, dep.line, f"{dep.name} {dep.version or dep.spec}",
                                                  detail=bad[1], title=f"{rule.title}: {dep.name}",
                                                  extra={"package": dep.name, "ecosystem": dep.ecosystem}))
                dep.issues.append(bad[1])
        for manifest, items in unlocked.items():
            resolved = [d for d in items if d.version]
            pending = [d for d in items if not d.version]
            detail = f"{len(items)} dependencies use version ranges and no lockfile pins them."
            if resolved:
                sample = ", ".join(f"{d.name} {d.spec} -> {d.version} ({d.resolved_by})" for d in resolved[:6])
                detail += (f" Secure Repo resolved {len(resolved)} of them virtually ({sample}{' ...' if len(resolved) > 6 else ''})"
                           " and checked those versions; see dependencies/lockfile-guide.md to create a real lockfile.")
            if pending:
                detail += " Not resolvable: " + ", ".join(d.name for d in pending[:10]) + (" ..." if len(pending) > 10 else "") + "."
            rule = RULES_BY_ID["SR-DEP-004"]
            self._add(self._finding_from_rule(rule, manifest, 0, manifest, detail=detail,
                                              extra={"unlocked": [d.name for d in items]}))
            for dep in items:
                dep.issues.append("Version range without lockfile" + (f" (resolved to {dep.version})" if dep.version else ""))
        for issue in issues:
            rule = RULES_BY_ID[issue.rule_id]
            self._add(self._finding_from_rule(rule, issue.manifest, issue.line,
                                              checks.redact_text(issue.snippet or issue.detail),
                                              detail=checks.redact_text(issue.detail)))

    def _vulnerability_findings(self, inventory: List[Dependency]) -> None:
        rule = RULES_BY_ID["SR-DEP-001"]
        for dep in inventory:
            if dep.vulnerabilities:
                worst = min((v["severity"] for v in dep.vulnerabilities), key=lambda s: SEVERITY_RANK.get(s, 9))
                ids = [v["aliases"][0] if v["aliases"] and v["aliases"][0].startswith("CVE-") else v["id"]
                       for v in dep.vulnerabilities]
                fixes = sorted({f for v in dep.vulnerabilities for f in v["fixed"]})
                count = len(dep.vulnerabilities)
                how = {"registry": " (version resolved from the declared range)", "environment": " (installed version)",
                       "registry-graph": f" (transitive, pulled in by {dep.parent})"}.get(dep.resolved_by or "", "")
                detail = (f"{dep.name} {dep.version}{how} ({dep.ecosystem}) is affected by {count} known "
                          f"vulnerabilit{'y' if count == 1 else 'ies'}: {', '.join(ids[:8])}"
                          f"{' ...' if len(ids) > 8 else ''}.")
                if fixes:
                    detail += f" Fixed in: {', '.join(fixes[:5])}."
                for vuln in dep.vulnerabilities:
                    if vuln["id"].startswith("MAL-"):
                        dep.issues.append("Flagged as malicious by OSV")
                self._add(self._finding_from_rule(
                    rule, dep.manifest, dep.line if dep.direct else 0, f"{dep.name}@{dep.version}", detail=detail,
                    severity=worst, title=f"Vulnerable library: {dep.name}@{dep.version}",
                    extra={"package": dep.name, "version": dep.version, "ecosystem": dep.ecosystem,
                           "direct": dep.direct, "vulnerabilities": dep.vulnerabilities, "fixed": fixes,
                           "resolved_by": dep.resolved_by}))
            if dep.latest and dep.version:
                current, latest = intel.major(dep.version), intel.major(dep.latest)
                if current is not None and latest is not None and latest > current:
                    self._add(self._finding_from_rule(
                        RULES_BY_ID["SR-DEP-007"], dep.manifest, dep.line, f"{dep.name} {dep.version} -> {dep.latest}",
                        detail=f"{dep.name} {dep.version} is {latest - current} major version(s) behind {dep.latest}.",
                        title=f"Outdated library: {dep.name}", extra={"package": dep.name, "ecosystem": dep.ecosystem}))
            if dep.licenses:
                risky = [lic for lic in dep.licenses if intel.COPYLEFT_RE.search(lic) or lic.lower() == "non-standard"]
                if risky:
                    self._add(self._finding_from_rule(
                        RULES_BY_ID["SR-DEP-008"], dep.manifest, dep.line, f"{dep.name}: {', '.join(dep.licenses)}",
                        detail=f"{dep.name} is licensed under {', '.join(dep.licenses)}.",
                        title=f"License review: {dep.name}", extra={"package": dep.name, "ecosystem": dep.ecosystem}))

    def _range_findings(self, inventory: List[Dependency]) -> None:
        candidates = [d for d in inventory if d.resolved_by == "registry" and d.range_lowest
                      and d.range_lowest != d.version and not d.vulnerabilities]
        if not candidates:
            return
        found = intel.osv_vulnerability_ids([(d.ecosystem, d.name, d.range_lowest) for d in candidates])
        rule = RULES_BY_ID["SR-DEP-009"]
        for dep in candidates:
            ids = found.get((dep.ecosystem, dep.name, dep.range_lowest))
            if not ids:
                continue
            self._add(self._finding_from_rule(
                rule, dep.manifest, dep.line, f"{dep.name} {dep.spec}",
                detail=(f"'{dep.name} {dep.spec}' resolves today to {dep.version} (not affected), but the range also "
                        f"admits {dep.range_lowest}, affected by {len(ids)} advisor{'y' if len(ids) == 1 else 'ies'} "
                        f"({', '.join(ids[:5])}). Raise the minimum version."),
                title=f"Range admits vulnerable releases: {dep.name}",
                extra={"package": dep.name, "ecosystem": dep.ecosystem, "range_lowest": dep.range_lowest, "advisories": ids}))
            dep.issues.append(f"Range admits vulnerable {dep.range_lowest}")

    def _stage_hygiene(self, files: List[FileInfo], workspace_path: str, has_deps: bool) -> Dict[str, bool]:
        paths = {f.rel.lower() for f in files}
        root_names = {p for p in paths if "/" not in p}
        facts = {
            "security_policy": bool(paths & {"security.md", ".github/security.md", "docs/security.md", "security.rst",
                                             "security.txt", ".well-known/security.txt"}),
            "dependency_updates": bool(paths & {".github/dependabot.yml", ".github/dependabot.yaml", "renovate.json",
                                                "renovate.json5", ".renovaterc", ".renovaterc.json",
                                                ".github/renovate.json", ".github/renovate.json5",
                                                ".gitlab/renovate.json"}),
            "license": any(p.startswith(("license", "licence", "copying")) for p in root_names),
            "ci": any(p.startswith((".github/workflows/", ".circleci/", ".buildkite/")) for p in paths) or bool(
                paths & {".gitlab-ci.yml", "azure-pipelines.yml", "jenkinsfile", "bitbucket-pipelines.yml",
                         ".travis.yml", ".drone.yml", "cloudbuild.yaml", "buildspec.yml"}),
            "codeowners": bool(paths & {"codeowners", ".github/codeowners", "docs/codeowners", ".gitlab/codeowners"}),
            "inventory": True,
        }
        gitignore = os.path.join(workspace_path, ".gitignore")
        content = ""
        if os.path.isfile(gitignore):
            try:
                with open(gitignore, encoding="utf-8", errors="replace") as handle:
                    content = handle.read()
            except OSError:
                pass
        facts["gitignore_secrets"] = bool(re.search(r"(?m)^\s*(?:\*\*/)?/?\.env(?:\*|\.\*|\b)|^\s*\*\.env\b|^\s*\*\.pem\b|^\s*\*\.key\b", content))
        facts["lockfiles"] = not any(f.rule_id == "SR-DEP-004" for f in self.findings)

        def missing(rule_id: str, detail: str, severity: Optional[str] = None) -> None:
            self._add(self._finding_from_rule(RULES_BY_ID[rule_id], ".", 0, detail=detail, severity=severity))

        if not facts["security_policy"]:
            missing("SR-HYG-001", "No SECURITY.md was found in the repository root, .github/ or docs/.")
        if not facts["gitignore_secrets"]:
            if content:
                missing("SR-HYG-002", ".gitignore exists but does not exclude .env / key files.", "low")
            else:
                missing("SR-HYG-002", "The repository has no .gitignore file.")
        if has_deps and not facts["dependency_updates"]:
            missing("SR-HYG-003", "Dependencies are declared but no Dependabot/Renovate configuration exists.")
        if not facts["license"]:
            missing("SR-HYG-004", "No LICENSE/COPYING file in the repository root.")
        if not facts["ci"]:
            missing("SR-HYG-005", "No CI configuration (GitHub Actions, GitLab CI, Jenkins, ...) was found.")
        if not facts["codeowners"]:
            missing("SR-HYG-006", "No CODEOWNERS file was found.")
        return facts

    # ------------------------------------------------------------------ configuration & learning
    def _decide_trust(self, workspace: Workspace) -> None:
        option = self.options.trust_repo_config
        if option is True:
            self.trusted, self.trust_reason = True, "explicitly trusted (--trust-repo-config)"
        elif option is False:
            self.trusted, self.trust_reason = False, "explicitly not trusted (--ignore-repo-config)"
        elif workspace.mode == "working-tree":
            self.trusted, self.trust_reason = True, "working tree of a local Git repository"
        else:
            self.trusted = False
            self.trust_reason = {"clone": "remote repository", "folder": "folder that is not a Git repository",
                                 "branch-export": "branch exported from a repository"}.get(workspace.mode, workspace.mode)
        self.bus.log(f"Audited repository is {'TRUSTED' if self.trusted else 'NOT trusted'}: {self.trust_reason}. "
                     + ("Its own configuration, shared triage and inline suppressions are applied (and reported)."
                        if self.trusted else
                        "Its own configuration, shared triage and inline suppressions are ignored."),
                     "ok" if self.trusted else "warn")

    def _load_configuration(self, workspace: Workspace) -> None:
        root = workspace.path
        self._decide_trust(workspace)
        user_dir = triage.data_dir() if self.options.learning else None
        self.config = load_config(root, user_dir, trust_repo=self.trusted)
        for error in self.config.errors:
            self.bus.log(f"Configuration: {error}", "warn")
        if self.config.source:
            self.bus.log(f"Project configuration loaded from {os.path.basename(self.config.source)}", "ok")
        if self.config.ignored_source:
            self.bus.log(f"{os.path.basename(self.config.ignored_source)} found in the audited repository was IGNORED "
                         f"(untrusted target; use --trust-repo-config to apply it)", "warn")
        self._min_conf_from_repo = self.config.repo_min_confidence
        # Disabled rules still run: their findings are kept with status "disabled_by_config" (audit trail).
        self.rules = list(PATTERN_RULES) + self.config.custom_rules
        self.path_rules = [r for r in self.rules if r.path]
        self._rule_cache.clear()
        if self.config.custom_rules:
            self.bus.log(f"{len(self.config.custom_rules)} custom rule(s) active", "ok")
        if self.config.min_confidence != "low" and self.options.min_confidence == "low":
            self.options.min_confidence = self.config.min_confidence

    def _apply_quality(self, findings: List[Dict], meta: Dict, workspace_path: str) -> Dict[str, int]:
        disabled = set(self.config.disable)
        for finding in findings:
            rule_id = finding["rule_id"]
            override = self.config.severity.get(rule_id)
            if override and override != finding["severity"]:
                finding.setdefault("extra", {}).update({
                    "original_severity": finding["severity"],
                    "severity_override_origin": "repo" if rule_id in self.config.repo_severity else "user"})
                finding["severity"] = override
            extra = finding.setdefault("extra", {})
            if (finding.get("in_test") and finding.get("source") == "code" and "original_severity" not in extra
                    and finding["severity"] in TEST_SEVERITY_STEP):
                # Test code is reported (it can hold real flaws) but one level lower: fixtures are not production.
                extra.update({"original_severity": finding["severity"], "test_downgrade": True})
                finding["severity"] = TEST_SEVERITY_STEP[finding["severity"]]
            finding["fingerprint"] = triage.fingerprint(finding)
            confidence.assess(finding, self.knowledge)
            if finding["status"] == "open" and rule_id in disabled:
                finding["status"] = "disabled_by_config"
                finding["triage"] = {"reason": "Rule disabled in the project configuration",
                                     "origin": "config" if rule_id in self.config.repo_disable else "user-config"}
        counts = {"decisions": 0, "learned_patterns": 0, "repo_decisions": 0, "repo_patterns": 0,
                  "allowlisted": 0, "below_min_confidence": 0}
        if self.knowledge is not None:
            key, _name = triage.project_key(meta)
            repo_payload = triage.load_repo_triage(workspace_path) if self.trusted else {}
            counts.update(self.knowledge.apply(findings, key, repo_payload))
        for finding in findings:
            if finding["status"] != "open":
                continue
            allowed = self.config.allowlisted(finding)
            if allowed:
                reason, from_repo = allowed
                finding["status"] = "false_positive"
                finding["triage"] = {"reason": reason, "origin": "config" if from_repo else "user-config"}
                counts["allowlisted"] += 1
            elif not confidence.meets(finding, self.options.min_confidence):
                finding["status"] = "filtered"
                finding["triage"] = {"reason": f"confidence below '{self.options.min_confidence}'",
                                     "origin": "config" if self._min_conf_from_repo else "filter"}
                counts["below_min_confidence"] += 1
        return counts

    def _repo_influence(self, findings: List[Dict], workspace: Workspace, excluded: List[str]) -> Dict:
        """Everything the audited repository itself did to shape the result (so the analyst can judge it)."""
        ignored: List[str] = []
        if self.config.ignored_source:
            ignored.append(f"{os.path.basename(self.config.ignored_source)} (project configuration)")
        if not self.trusted and os.path.isfile(os.path.join(workspace.path, triage.REPO_TRIAGE_FILE)):
            ignored.append(".securerepo/triage.json (shared triage decisions)")
        if not self.trusted and self.inline_ignored:
            ignored.append(f"{self.inline_ignored} inline suppression comment(s) (nosec / securerepo:ignore)")
        disabled: Dict[str, Dict] = {}
        overrides: Dict[Tuple[str, str, str], Dict] = {}
        counts = {"allowlisted": 0, "repo_decisions": 0, "repo_patterns": 0, "inline": 0, "inline_without_rule_id": 0}
        for finding in findings:
            origin = (finding.get("triage") or {}).get("origin")
            if finding["status"] == "disabled_by_config":
                entry = disabled.setdefault(finding["rule_id"], {
                    "rule_id": finding["rule_id"], "title": finding["title"], "hidden": 0,
                    "from": "repo" if origin == "config" else "user"})
                entry["hidden"] += 1
            elif finding["status"] == "false_positive" and origin in ("config", "user-config"):
                counts["allowlisted"] += 1
            elif origin == "repo-decision":
                counts["repo_decisions"] += 1
            elif origin == "repo-pattern":
                counts["repo_patterns"] += 1
            elif origin == "inline":
                counts["inline"] += 1
                if not (finding.get("triage") or {}).get("rule_ids"):
                    counts["inline_without_rule_id"] += 1
            extra = finding.get("extra") or {}
            if extra.get("severity_override_origin"):
                key = (finding["rule_id"], extra["original_severity"], finding["severity"])
                entry = overrides.setdefault(key, {"rule_id": finding["rule_id"], "from_severity": key[1],
                                                   "to_severity": key[2], "count": 0,
                                                   "from": "repo" if extra["severity_override_origin"] == "repo" else "user"})
                entry["count"] += 1
        patterns = [{"pattern": p, "from": "repo" if p in self.config.repo_exclude else "user"}
                    for p in self.config.exclude]
        return {
            "trusted": self.trusted, "trust_reason": self.trust_reason,
            "repo_config_file": os.path.basename(self.config.source) if self.config.source else None,
            "ignored": ignored,
            "disabled_rules": sorted(disabled.values(), key=lambda e: -e["hidden"]),
            "severity_overrides": sorted(overrides.values(), key=lambda e: -e["count"]),
            "excluded_by_config": {"patterns": patterns, "files": len(excluded), "sample": excluded[:50]},
            "ignore_file_markers": list(self.ignore_markers[:50]),
            **counts,
        }

    # ------------------------------------------------------------------ main
    def run(self, target: Target, interactive: bool = False, write_reports: bool = True) -> Tuple[Dict, Optional[str]]:
        from secure_repo.report.writer import write_reports as write_all  # local import avoids cycles

        started = time.time()
        started_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")
        bus = self.bus
        workspace: Optional[Workspace] = None
        try:
            bus.stage("acquire", "start")
            bus.log(f"Target: {target.location} ({'remote URL' if target.kind == 'remote' else 'local path'})")
            workspace = prepare_workspace(target, bus, interactive=interactive)
            bus.stage("acquire", "done", f"{workspace.mode} @ {workspace.branch or 'n/a'}")
            self._check_cancel()
            self._load_configuration(workspace)

            bus.stage("enumerate", "start")
            files = enumerate_files(workspace.path, self.options.exclude + self.config.exclude,
                                    skipped=self.not_analyzed["directories"])
            excluded_by_config: List[str] = []
            if self.config.exclude:  # which files did the configuration take out of the analysis?
                kept = {f.rel for f in files}
                excluded_by_config = [f.rel for f in enumerate_files(workspace.path, self.options.exclude)
                                      if f.rel not in kept]
                bus.log(f"The configuration excludes {len(excluded_by_config)} file(s) from the analysis "
                        f"({', '.join(self.config.exclude[:6])}{' ...' if len(self.config.exclude) > 6 else ''})", "warn")
            tree = StructureTree(workspace.name, files)
            bus.emit("structure", tree=tree.to_dict(), files=len(files))
            directories = sum(1 for node in tree.index.values() if node["type"] == "dir") - 1
            bus.log(f"Mapped {len(files)} files in {directories} directories", "ok")
            bus.stage("enumerate", "done", f"{len(files)} files")

            bus.stage("analyze", "start")
            stats = {"scanned": 0, "skipped": 0, "lines": 0, "languages": {}}
            self._stage_analyze(files, tree, stats)
            engines = self.engine_stats
            bus.log(f"Engines: {engines['python_ast']} Python syntax trees, {engines['js_flow']} JS/TS data-flow passes, "
                    f"{engines['masked_files']} files lexically masked; {sum(self.noise.values())} noisy matches discarded", "ok")
            bus.stage("analyze", "done", f"{stats['scanned']} files analyzed, {len(self.findings)} findings")

            bus.stage("dependencies", "start")
            inventory, issues, manifests = self._stage_dependencies(files)
            direct = sum(1 for d in inventory if d.direct)
            bus.stage("dependencies", "done", f"{len(inventory)} libraries ({direct} direct) in {len(manifests)} manifests")

            bus.stage("resolve", "start")
            resolution = self._stage_resolve(inventory, workspace.path)
            unresolved = sum(1 for d in inventory if d.direct and not d.version and d.source == "registry")
            if any(resolution.values()) or unresolved:
                bus.stage("resolve", "done", f"environment {resolution['environment']} · registry {resolution['registry']}"
                                             f" · graph +{resolution['graph']} · unresolved {unresolved}")
            else:
                bus.stage("resolve", "skip", "every version already pinned" if inventory else "no dependencies")
            self._dependency_findings(inventory, issues)

            online = not self.options.offline
            queried = 0
            intel_error = ""
            bus.stage("intel", "start")
            if not online:
                bus.log("Offline mode - skipping OSV.dev and deps.dev lookups", "warn")
                bus.stage("intel", "skip", "offline mode")
            elif not inventory:
                bus.stage("intel", "skip", "no dependencies")
            else:
                try:
                    queried, vulnerable = intel.osv_lookup(inventory, bus)
                    if self.options.enrich:
                        intel.depsdev_enrich(inventory, bus)
                    self._vulnerability_findings(inventory)
                    self._range_findings(inventory)
                    bus.stage("intel", "done", f"{queried} versions checked, {vulnerable} vulnerable")
                except (urllib.error.URLError, OSError, ValueError) as exc:
                    intel_error = str(getattr(exc, "reason", exc))
                    bus.log(f"Vulnerability intelligence unavailable: {intel_error}", "warn")
                    self._vulnerability_findings(inventory)
                    bus.stage("intel", "skip", "network unavailable")

            bus.stage("hygiene", "start")
            hygiene = self._stage_hygiene(files, workspace.path, bool(inventory))
            bus.stage("hygiene", "done", f"{sum(hygiene.values())}/{len(hygiene)} practices present")

            meta = {
                "name": workspace.name, "target": target.location, "target_kind": target.kind,
                "branch": workspace.branch, "commit": workspace.commit, "mode": workspace.mode,
                "remote": checks.redact_text(workspace.remote), "started_at": started_iso,
                "platform": f"{platform.system()} {platform.release()} ({platform.machine()})",
                "python": platform.python_version(), "git": gitops.git_version(),
                "auditor": self.options.auditor or "not specified",
                "options": {"offline": self.options.offline, "compliance": self.options.compliance,
                            "frameworks": compliance.resolve_frameworks(self.options.frameworks)
                            if self.options.compliance else [],
                            "include_tests": self.options.include_tests, "min_confidence": self.options.min_confidence,
                            "learning": self.options.learning, "max_file_size": self.options.max_file_size,
                            "exclude": self.options.exclude + self.config.exclude,
                            "trust_repo_config": self.trusted, "trust_reason": self.trust_reason},
                "notes": workspace.notes + ([f"Vulnerability intelligence unavailable: {intel_error}"] if intel_error else []),
            }

            # Quality pipeline: fingerprints, confidence, triage knowledge, configuration --------------
            findings = [f.to_dict() for f in self.findings]
            quality = self._apply_quality(findings, meta, workspace.path)
            influence = self._repo_influence(findings, workspace, excluded_by_config)
            if quality["decisions"] or quality["learned_patterns"]:
                bus.log(f"Triage knowledge applied: {quality['decisions']} decision(s), "
                        f"{quality['learned_patterns']} learned false-positive pattern match(es)", "ok")
            findings.sort(key=lambda f: (f["status"] in SUPPRESSED_STATUSES, SEVERITY_RANK.get(f["severity"], 9),
                                         f["file"], f["line"], f["rule_id"]))
            for number, finding in enumerate(findings, 1):
                finding["id"] = f"SR-{number:04d}"

            bus.stage("compliance", "start")
            bus.stage("scoring", "start")
            finished = time.time()
            meta["finished_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
            meta["duration_seconds"] = round(finished - started, 2)
            vulnerable_deps = [d for d in inventory if d.vulnerabilities]
            ecosystems: Dict[str, int] = {}
            for dep in inventory:
                ecosystems[dep.ecosystem] = ecosystems.get(dep.ecosystem, 0) + 1
            direct = sum(1 for d in inventory if d.direct)
            inventory.sort(key=lambda d: (not d.vulnerabilities, not d.direct, d.ecosystem, d.name.lower()))
            report = {
                "schema": "secure-repo/report@1",
                "tool": {"name": "Secure Repo", "version": __version__, "author": __author__, "rules": len(RULES)},
                "meta": meta,
                "summary": {"files_total": len(files), "files_scanned": stats["scanned"],
                            "files_skipped": stats["skipped"], "lines": stats["lines"]},
                "findings": findings,
                "rules": {},
                "owasp": OWASP_TOP10,
                "dependencies": [d.to_dict() for d in inventory],
                "dependency_summary": {
                    "total": len(inventory), "direct": direct, "transitive": len(inventory) - direct,
                    "ecosystems": ecosystems, "manifests": manifests, "vulnerable": len(vulnerable_deps),
                    "vulnerabilities": len({v["id"] for d in vulnerable_deps for v in d.vulnerabilities}),
                    "queried": queried, "online": online and not intel_error,
                    "resolution": resolver.summarize(inventory),
                },
                "lockfile": resolver.virtual_lockfile(inventory),
                "analysis": {
                    "engines": dict(self.engine_stats), "noise_filtered": dict(sorted(self.noise.items())),
                    "noise_total": sum(self.noise.values()), "knowledge": quality,
                    "learning": self.options.learning, "config": os.path.basename(self.config.source) if self.config.source else None,
                    "custom_rules": [r.id for r in self.config.custom_rules], "min_confidence": self.options.min_confidence,
                    "repo_influence": influence,
                    "not_analyzed": self.not_analyzed,
                },
                "structure": tree.to_dict(),
                "languages": stats["languages"],
                "hygiene": hygiene,
                "compliance": {"enabled": False, "frameworks": []},
            }
            summarymod.finalize(report, {r.id: r.to_dict() for r in self.config.custom_rules})
            if report["compliance"].get("enabled"):
                names = ", ".join(f"{fw['name']} {fw['score']}%" for fw in report["compliance"]["frameworks"])
                bus.stage("compliance", "done", names)
            else:
                bus.stage("compliance", "skip", "disabled")
            bus.stage("scoring", "done", f"score {report['summary']['score']}/100 grade {report['summary']['grade']}"
                                         + (f" · {report['summary']['suppressed']} suppressed" if report['summary']['suppressed'] else ""))

            report_dir = None
            if write_reports:
                bus.stage("report", "start")
                report_dir = write_all(report, self.options.output_dir, bus, tree_text=tree.render_text(),
                                       log_lines=self.log_lines)
                bus.stage("report", "done", report_dir)
            else:
                bus.stage("report", "skip", "report writing disabled")
            bus.emit("done", summary=report["summary"], report_dir=report_dir)
            return report, report_dir
        except ScanCancelled as exc:
            bus.emit("error", message=str(exc))
            raise
        except Exception as exc:
            bus.log(f"Scan failed: {exc}", "error")
            bus.emit("error", message=str(exc))
            raise
        finally:
            if workspace is not None:
                workspace.cleanup()
