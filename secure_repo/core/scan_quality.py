"""Trust, configuration, baseline / --since, hygiene facts and the quality pass over findings."""

from __future__ import annotations

import os
import re
from typing import Dict, List, Optional, Tuple

from secure_repo.core import confidence, gitops, triage
from secure_repo.core.config import load_config
from secure_repo.core.scan_base import ScannerBase
from secure_repo.core.rules import PATTERN_RULES, RULES_BY_ID
from secure_repo.core.scan_common import TEST_SEVERITY_STEP, load_baseline
from secure_repo.core.walker import FileInfo
from secure_repo.core.workspace import Workspace


class QualityMixin(ScannerBase):
    def _files_since(self, workspace: Workspace, files: List[FileInfo]) -> List[FileInfo]:
        """Restrict the analysis to the files that changed relative to ``options.since`` (local working tree only)."""
        if workspace.mode != "working-tree":
            raise ValueError("--since works on the working tree of a local Git repository (not on remote repositories, "
                             "other branches or plain folders)")
        changed = gitops.changed_files(workspace.path, self.options.since)
        selected = [f for f in files if f.rel in changed]
        self.not_analyzed["since"] = {"ref": self.options.since, "changed": len(selected),
                                      "unchanged_skipped": len(files) - len(selected)}
        self.bus.log(f"--since {self.options.since}: analyzing {len(selected)} changed file(s); "
                     f"{len(files) - len(selected)} unchanged file(s) are not analyzed", "ok")
        return selected

    def _apply_baseline(self, findings: List[Dict]) -> Optional[Dict]:
        """Mark each finding as new or already present in the baseline report (matched by fingerprint)."""
        if not self.options.baseline:
            return None
        known = load_baseline(self.options.baseline)
        new = 0
        for finding in findings:
            state = "existing" if finding.get("fingerprint") in known else "new"
            finding.setdefault("extra", {})["baseline"] = state
            new += int(state == "new" and finding["status"] == "open")
        self.bus.log(f"Baseline {os.path.basename(self.options.baseline)}: {new} new open finding(s), "
                     f"{sum(1 for f in findings if f['extra']['baseline'] == 'existing')} already known", "ok")
        return {"file": os.path.basename(self.options.baseline), "known_fingerprints": len(known), "new_open": new}

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
