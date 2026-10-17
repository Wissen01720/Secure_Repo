"""File analysis: every engine applied to each file, in this process or in worker processes."""

from __future__ import annotations

import bisect
import os
import pickle
import re
import time
from concurrent.futures import ProcessPoolExecutor
from concurrent.futures.process import BrokenProcessPool
from typing import Dict, List, Optional, Tuple

from secure_repo.core import checks, jsflow, lexer, pyast, regions, thirdparty, webchecks
from secure_repo.core.languages import DOCUMENTATION
from secure_repo.core.models import SEVERITY_RANK, Finding
from secure_repo.core.scan_base import ScannerBase
from secure_repo.core.rules import RULES_BY_ID, Rule, canonical_rule_id
from secure_repo.core.scan_common import (
    COMMENT_PREFIXES,
    COMMENT_START_RE,
    DIRECTIVE_RE,
    EVIDENCE_LIMIT,
    IGNORE_FILE_MARKER,
    MARKUP_EXTENSIONS,
    MAX_AUTO_JOBS,
    MAX_EVIDENCE_LINES,
    MAX_PER_RULE_PER_FILE,
    MINIFIABLE_LANGUAGES,
    RULE_ID_RE,
)
from secure_repo.core.walker import FileInfo, StructureTree, read_text


class AnalysisMixin(ScannerBase):
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

        if views is not None and info.language in lexer.JS_LIKE and not in_test:
            facts = webchecks.express_facts(views["no_comments"])
            if facts["express"] or facts["state_routes"] or facts["csrf"]:
                line_no, _masked, column = locate(max(facts["session_offset"], 0))
                facts.update(file=info.rel, session_line=line_no if facts["session_offset"] >= 0 else 0,
                             snippet=self._snippet(line_text_of(line_no), column) if facts["session_offset"] >= 0 else "")
                self.web_facts.append(facts)
        if views is not None and info.language == "Python" and "MIDDLEWARE" in text:
            for offset, detail in webchecks.django_csrf_issues(views["no_comments"]):
                line_no, _masked, column = locate(offset)
                file_findings.append(self._finding_from_rule(
                    RULES_BY_ID[webchecks.RULE_DJANGO_CSRF], info.rel, line_no,
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
                chosen = by_key.get((finding.rule_id, finding.line))
                if finding.rule_id not in jsflow.HANDLED_RULES or chosen is None:
                    kept.append(finding)
                    continue
                covered.add((finding.rule_id, finding.line))
                if chosen.kind == "constant":
                    self._count_noise("javascript: constant or superseded sink")
                    continue
                if chosen.kind == "tainted":
                    finding.severity = chosen.severity or finding.severity
                    finding.engine, finding.flow, finding.detail = "taint", chosen.flow, chosen.detail
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
        findings_before, facts_before = len(self.findings), len(self.web_facts)
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
            outcome["web_facts"] = self.web_facts[facts_before:]
            del self.web_facts[facts_before:]
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
        from secure_repo.core import scanner as scanner_module  # late import: scanner imports this module

        done = 0
        if workers > 1:
            pool = None
            try:
                pool = ProcessPoolExecutor(max_workers=workers, initializer=scanner_module._init_worker,
                                           initargs=(self.options, self.config, self.trusted))
                self.bus.log(f"Analyzing {len(files)} files with {workers} worker processes", "ok")
                chunk = max(1, min(32, len(files) // (workers * 8)))
                for outcome in pool.map(scanner_module._worker_process, files, chunksize=chunk):
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
        self.web_facts.extend(outcome.pop("web_facts", []))
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
        for issue in webchecks.express_csrf_findings(self.web_facts):
            self._add(self._finding_from_rule(RULES_BY_ID[webchecks.RULE_EXPRESS_CSRF], issue["file"], issue["line"],
                                              issue["snippet"], detail=issue["detail"], engine="lexical"))
