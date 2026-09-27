"""Scan orchestrator: runs every analysis stage and assembles the report."""

from __future__ import annotations

import bisect
import os
import platform
import re
import sys
import time
import urllib.error
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from secure_repo import __author__, __version__
from secure_repo.core import checks, compliance, deps as depmod, gitops, intel
from secure_repo.core.events import EventBus
from secure_repo.core.languages import DOCUMENTATION, PROGRAMMING
from secure_repo.core.models import (OWASP_TOP10, SEVERITIES, SEVERITY_RANK, Dependency, Finding, owasp_key)
from secure_repo.core.rules import PATTERN_RULES, RULES, RULES_BY_ID, Rule
from secure_repo.core.scoring import compute_score
from secure_repo.core.walker import FileInfo, StructureTree, enumerate_files, read_text
from secure_repo.core.workspace import Target, Workspace, prepare_workspace

NOSEC_RE = re.compile(r"(?i)\bnosec\b|securerepo:ignore\b|noqa:\s*secure")
COMMENT_PREFIXES = ("#", "//", "/*", "* ", "*/", "--", "<!--", ";", "rem ", "REM ", "::")
MAX_PER_RULE_PER_FILE = 50
STRING_AWARE = PROGRAMMING - {"Shell", "PowerShell", "Batch"}
PATH_RULES = [rule for rule in PATTERN_RULES if rule.path]


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
    output_dir: str = "secure-repo-reports"

    def to_dict(self) -> Dict:
        return asdict(self)


class ScanCancelled(Exception):
    pass


class Scanner:
    def __init__(self, options: ScanOptions, bus: Optional[EventBus] = None):
        self.options = options
        self.bus = bus or EventBus()
        self.findings: List[Finding] = []
        self.cancelled = False
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

    def _add(self, finding: Finding) -> None:
        self.findings.append(finding)
        self.bus.emit("finding", rule_id=finding.rule_id, title=finding.title, severity=finding.severity,
                      file=finding.file, line=finding.line, category=finding.category)

    def _finding_from_rule(self, rule: Rule, info_rel: str, line: int, snippet: str = "", detail: str = "",
                           severity: Optional[str] = None, in_test: bool = False, title: Optional[str] = None,
                           extra: Optional[Dict] = None) -> Finding:
        return Finding(rule_id=rule.id, title=title or rule.title, severity=severity or rule.severity,
                       category=rule.category, file=info_rel, line=line, snippet=snippet, detail=detail,
                       cwe=rule.cwe, owasp=owasp_key(rule.owasp), tags=list(rule.tags), confidence=rule.confidence,
                       source=rule.source, in_test=in_test, extra=extra or {})

    def _rules_for(self, info: FileInfo) -> List[Rule]:
        path_signature = tuple(rule.id for rule in PATH_RULES if rule.applies_to(info.language, info.rel))
        key = (info.language, path_signature)
        cached = self._rule_cache.get(key)
        if cached is None:
            cached = [rule for rule in PATTERN_RULES if rule.applies_to(info.language, info.rel)]
            self._rule_cache[key] = cached
        return cached

    @staticmethod
    def _inside_string(line_text: str, column: int) -> bool:
        """True when ``column`` falls inside a single-line string literal (e.g. a message or docstring)."""
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
    def _snippet(line_text: str, column: int) -> str:
        stripped = line_text.strip()
        offset = len(line_text) - len(line_text.lstrip())
        column = max(0, column - offset)
        if len(stripped) > 220:
            start = max(0, column - 80)
            stripped = ("…" if start else "") + stripped[start:start + 200] + "…"
        return checks.redact_text(stripped)

    # ------------------------------------------------------------------ analysis
    def analyze_text(self, info: FileInfo, text: str) -> None:
        lower = text.lower()
        newlines: Optional[List[int]] = None
        lines: Optional[List[str]] = None
        secret_lines = set()

        def locate(offset: int) -> Tuple[int, str, int]:
            nonlocal newlines, lines
            if newlines is None:
                newlines = [m.start() for m in re.finditer("\n", text)]
                lines = text.split("\n")
            index = bisect.bisect_right(newlines, offset - 1) if offset else 0
            line_start = newlines[index - 1] + 1 if index > 0 else 0
            return index + 1, lines[index] if index < len(lines) else "", offset - line_start

        in_test = info.in_test
        is_doc = info.language in DOCUMENTATION
        string_aware = info.language in STRING_AWARE
        for rule in self._rules_for(info):
            if rule.keywords and not any(keyword in lower for keyword in rule.keywords):
                continue
            regex = rule.regex
            if regex is None:
                continue
            seen = set()
            for match in regex.finditer(text):
                line_no, line_text, column = locate(match.start())
                if line_no in seen:
                    continue
                if not rule.scan_comments and line_text.lstrip().startswith(COMMENT_PREFIXES):
                    continue
                if NOSEC_RE.search(line_text):
                    continue
                if rule.exclude_re and rule.exclude_re.search(line_text):
                    continue
                if string_aware and rule.source == "code" and self._inside_string(line_text, column):
                    end = column + max(len(match.group(0).split("\n", 1)[0]) - 1, 0)
                    if self._inside_string(line_text, end):
                        continue  # the whole match lives inside a string literal (message, docstring...)
                seen.add(line_no)
                severity = rule.severity
                if is_doc and rule.source == "code":
                    continue  # code patterns inside documentation are examples, not code
                if is_doc and rule.source == "secret" and SEVERITY_RANK[severity] < SEVERITY_RANK["medium"]:
                    severity = "medium"
                if rule.source == "secret":
                    secret_lines.add(line_no)
                self._add(self._finding_from_rule(rule, info.rel, line_no, self._snippet(line_text, column),
                                                  severity=severity, in_test=in_test))
                if len(seen) >= MAX_PER_RULE_PER_FILE:
                    break

        if info.language != "Other" or os.path.basename(info.rel).startswith("."):
            generic = RULES_BY_ID["SR-SEC-019"]
            for offset, key, value, entropy in checks.find_generic_credentials(text, info.language):
                line_no, line_text, column = locate(offset)
                if line_no in secret_lines or NOSEC_RE.search(line_text):
                    continue
                secret_lines.add(line_no)
                severity = "high" if entropy >= 3.0 or len(value) >= 12 else "medium"
                if is_doc:
                    severity = "low"
                detail = (f"'{key}' is assigned a literal value ({len(value)} characters, entropy "
                          f"{entropy:.2f} bits/char). Value redacted: {checks.mask(value)}")
                self._add(self._finding_from_rule(generic, info.rel, line_no, self._snippet(line_text, column),
                                                  detail=detail, severity=severity, in_test=in_test))

        if any(ch.isdigit() for ch in text[:200000]):
            card_rule = RULES_BY_ID["SR-PII-001"]
            for offset, number, is_test_card in checks.find_card_numbers(text):
                line_no, line_text, column = locate(offset)
                if NOSEC_RE.search(line_text):
                    continue
                digits = re.sub(r"\D", "", number)
                detail = f"Card number {digits[:4]}********{digits[-2:]} passes the Luhn check."
                severity = card_rule.severity
                if is_test_card:
                    severity, detail = "info", detail + " It is a well-known test card number."
                self._add(self._finding_from_rule(card_rule, info.rel, line_no,
                                                  self._snippet(line_text.replace(number, checks.mask(number)), column),
                                                  detail=detail, severity=severity, in_test=in_test))

        if info.language == "Dockerfile":
            for rule_id, line_no, snippet, detail in checks.analyze_dockerfile(text):
                self._add(self._finding_from_rule(RULES_BY_ID[rule_id], info.rel, line_no, snippet, detail=detail,
                                                  in_test=in_test))

    # ------------------------------------------------------------------ stages
    def _stage_analyze(self, files: List[FileInfo], tree: StructureTree, stats: Dict) -> None:
        total = len(files)
        batch: List[str] = []
        last_emit = time.time()
        languages: Dict[str, Dict[str, int]] = {}
        for index, info in enumerate(files, 1):
            self._check_cancel()
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
                stats["skipped"] += 1
            else:
                line_count = text.count("\n") + (0 if text.endswith("\n") or not text else 1)
                tree.set_lines(info.rel, line_count)
                lang = languages.setdefault(info.language, {"files": 0, "lines": 0, "bytes": 0})
                lang["files"] += 1
                lang["lines"] += line_count
                lang["bytes"] += info.size
                stats["lines"] += line_count
                minified = len(text) > 20000 and line_count < len(text) / 1500
                ignored = "securerepo:ignore-file" in text[:2000]
                if info.scannable and not minified and not ignored and (self.options.include_tests or not info.in_test):
                    self.analyze_text(info, text)
                    stats["scanned"] += 1
                else:
                    stats["skipped"] += 1
            batch.append(info.rel)
            now = time.time()
            if now - last_emit > 0.12 or index == total:
                self.bus.emit("files", paths=batch, done=index, total=total)
                self.bus.progress("analyze", index, total, info.rel)
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
            try:
                result = parser(text, info.rel, issues)
            except Exception as exc:  # malformed manifest - report and continue
                self.bus.log(f"Could not parse {info.rel}: {exc}", "warn")
                continue
            for dep in result:
                if is_lock:
                    dep.direct = dep.direct and parser is depmod.parse_nuget_lock
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
                    break

        inventory: Dict[Tuple[str, str, str], Dependency] = {}
        for dep, is_lock in sorted(parsed, key=lambda item: item[1]):
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

    def _dependency_findings(self, inventory: List[Dependency], issues: List[depmod.ParseIssue]) -> None:
        unlocked: Dict[str, List[Dependency]] = {}
        for dep in inventory:
            if dep.direct and not dep.locked and not dep.version and dep.source == "registry" \
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
            names = ", ".join(sorted(d.name for d in items)[:15]) + (" ..." if len(items) > 15 else "")
            rule = RULES_BY_ID["SR-DEP-004"]
            self._add(self._finding_from_rule(rule, manifest, 0, manifest,
                                              detail=f"{len(items)} dependencies use version ranges and no lockfile "
                                                     f"pins them: {names}"))
            for dep in items:
                dep.issues.append("Version not pinned and no lockfile")
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
                detail = (f"{dep.name} {dep.version} ({dep.ecosystem}) is affected by {count} known "
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
                           "direct": dep.direct, "vulnerabilities": dep.vulnerabilities, "fixed": fixes}))
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
                with open(gitignore, "r", encoding="utf-8", errors="replace") as handle:
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

            bus.stage("enumerate", "start")
            files = enumerate_files(workspace.path, self.options.exclude)
            tree = StructureTree(workspace.name, files)
            bus.emit("structure", tree=tree.to_dict(), files=len(files))
            directories = sum(1 for node in tree.index.values() if node["type"] == "dir") - 1
            bus.log(f"Mapped {len(files)} files in {directories} directories", "ok")
            bus.stage("enumerate", "done", f"{len(files)} files")

            bus.stage("analyze", "start")
            stats = {"scanned": 0, "skipped": 0, "lines": 0, "languages": {}}
            self._stage_analyze(files, tree, stats)
            code_findings = len(self.findings)
            bus.stage("analyze", "done", f"{stats['scanned']} files analyzed, {code_findings} findings")

            bus.stage("dependencies", "start")
            inventory, issues, manifests = self._stage_dependencies(files)
            self._dependency_findings(inventory, issues)
            direct = sum(1 for d in inventory if d.direct)
            bus.stage("dependencies", "done", f"{len(inventory)} libraries ({direct} direct) in {len(manifests)} manifests")

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
                    bus.stage("intel", "done", f"{queried} versions checked, {vulnerable} vulnerable")
                except (urllib.error.URLError, OSError, ValueError) as exc:
                    intel_error = str(getattr(exc, "reason", exc))
                    bus.log(f"Vulnerability intelligence unavailable: {intel_error}", "warn")
                    self._vulnerability_findings(inventory)
                    bus.stage("intel", "skip", "network unavailable")

            bus.stage("hygiene", "start")
            hygiene = self._stage_hygiene(files, workspace.path, bool(inventory))
            bus.stage("hygiene", "done", f"{sum(hygiene.values())}/{len(hygiene)} practices present")

            # Finalize findings -------------------------------------------------
            self.findings.sort(key=lambda f: (SEVERITY_RANK.get(f.severity, 9), f.file, f.line, f.rule_id))
            for number, finding in enumerate(self.findings, 1):
                finding.id = f"SR-{number:04d}"
                tree.add_finding(finding.file, finding.severity)
            findings = [f.to_dict() for f in self.findings]

            bus.stage("compliance", "start")
            compliance_result: Dict = {"enabled": False, "frameworks": []}
            if self.options.compliance:
                compliance_result = compliance.evaluate(findings, hygiene, self.options.frameworks)
                names = ", ".join(f"{fw['name']} {fw['score']}%" for fw in compliance_result["frameworks"])
                bus.stage("compliance", "done", names)
            else:
                bus.stage("compliance", "skip", "disabled")

            bus.stage("scoring", "start")
            score = compute_score(findings)
            by_severity = {s: 0 for s in SEVERITIES}
            by_category: Dict[str, int] = {}
            by_owasp: Dict[str, int] = {}
            per_file: Dict[str, Dict] = {}
            for finding in findings:
                by_severity[finding["severity"]] += 1
                by_category[finding["category"]] = by_category.get(finding["category"], 0) + 1
                by_owasp[finding["owasp"]] = by_owasp.get(finding["owasp"], 0) + 1
                entry = per_file.setdefault(finding["file"], {"file": finding["file"], "count": 0, "risk": finding["severity"]})
                entry["count"] += 1
            top_files = sorted(per_file.values(), key=lambda e: (SEVERITY_RANK[e["risk"]], -e["count"]))[:15]
            bus.stage("scoring", "done", f"score {score['score']}/100 grade {score['grade']}")

            finished = time.time()
            vulnerable_deps = [d for d in inventory if d.vulnerabilities]
            ecosystems: Dict[str, int] = {}
            for dep in inventory:
                ecosystems[dep.ecosystem] = ecosystems.get(dep.ecosystem, 0) + 1
            used_rules = sorted({f["rule_id"] for f in findings})
            inventory.sort(key=lambda d: (not d.vulnerabilities, not d.direct, d.ecosystem, d.name.lower()))
            report = {
                "schema": "secure-repo/report@1",
                "tool": {"name": "Secure Repo", "version": __version__, "author": __author__, "rules": len(RULES)},
                "meta": {
                    "name": workspace.name, "target": target.location, "target_kind": target.kind,
                    "branch": workspace.branch, "commit": workspace.commit, "mode": workspace.mode,
                    "remote": checks.redact_text(workspace.remote), "started_at": started_iso,
                    "finished_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    "duration_seconds": round(finished - started, 2),
                    "platform": f"{platform.system()} {platform.release()} ({platform.machine()})",
                    "python": platform.python_version(), "git": gitops.git_version(),
                    "auditor": self.options.auditor or "not specified",
                    "options": {"offline": self.options.offline, "compliance": self.options.compliance,
                                "frameworks": compliance.resolve_frameworks(self.options.frameworks)
                                if self.options.compliance else [],
                                "include_tests": self.options.include_tests,
                                "max_file_size": self.options.max_file_size, "exclude": self.options.exclude},
                    "notes": workspace.notes + ([f"Vulnerability intelligence unavailable: {intel_error}"] if intel_error else []),
                },
                "summary": {
                    "files_total": len(files), "files_scanned": stats["scanned"], "files_skipped": stats["skipped"],
                    "lines": stats["lines"], "findings": len(findings), "by_severity": by_severity,
                    "by_category": dict(sorted(by_category.items(), key=lambda kv: -kv[1])),
                    "by_owasp": {k: by_owasp[k] for k in OWASP_TOP10 if k in by_owasp},
                    "score": score["score"], "grade": score["grade"], "top_files": top_files,
                },
                "findings": findings,
                "rules": {rid: RULES_BY_ID[rid].to_dict() for rid in used_rules},
                "owasp": OWASP_TOP10,
                "dependencies": [d.to_dict() for d in inventory],
                "dependency_summary": {
                    "total": len(inventory), "direct": direct, "transitive": len(inventory) - direct,
                    "ecosystems": ecosystems, "manifests": manifests, "vulnerable": len(vulnerable_deps),
                    "vulnerabilities": len({v["id"] for d in vulnerable_deps for v in d.vulnerabilities}),
                    "queried": queried, "online": online and not intel_error,
                },
                "structure": tree.to_dict(),
                "languages": stats["languages"],
                "hygiene": hygiene,
                "compliance": compliance_result,
            }

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

