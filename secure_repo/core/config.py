"""Project configuration (``.securerepo.toml``) and user-level custom rules.

Lets a team tune the analysis for its code base: disable noisy rules, change severities,
allow-list known-safe paths or values, set a minimum confidence and add custom detection rules.
"""

from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass, field

from secure_repo.core import redos
from secure_repo.core.models import SEVERITIES
from secure_repo.core.rules import RULES_BY_ID, Rule, canonical_rule_id

import tomllib as _toml

CONFIG_NAMES = (".securerepo.toml", "securerepo.toml")
CONFIDENCE_LEVELS = ("low", "medium", "high")

TEMPLATE = '''# Secure Repo project configuration - https://github.com/Wissen01720/Secure_Repo
# Commit this file so every analyst and CI job applies the same tuning.
#
# Trust: this file is applied when you audit the working tree of your own local Git repository. It is IGNORED
# for remote repositories, other branches and plain folders (an audited repo must not grade itself) unless you
# pass --trust-repo-config. The report always lists what it changed.

[scan]
# Paths that are not analyzed at all (glob patterns, relative to the repository root).
exclude = ["docs/examples/*", "third_party/*"]
# Findings below this confidence are filtered out: "low" (show everything), "medium" or "high".
min_confidence = "low"

[rules]
# Rules that make no sense for this project.
disable = []

[rules.severity]
# Override a rule's severity, e.g. "SR-GEN-006" = "info"
# "SR-GEN-006" = "info"

[intel]
# Package names that must never leave your machine: they are not resolved against any registry, not sent to
# OSV.dev and not looked up on deps.dev. Glob patterns, case-insensitive. Use it for internal packages.
# private = ["@mycompany/*", "mycompany-*", "com.mycompany:*"]

[allowlist]
# Findings in these paths are kept in the report but marked as false positives (audit trail).
paths = []
# Regular expressions matched against the (redacted) evidence of a finding.
values = []

# Custom detection rules. "context" = "code" (strings & comments masked), "strings" (comments masked)
# or "raw" (whole text, e.g. for secrets). "languages" uses Secure Repo language names or ["*"].
# [[custom_rules]]
# id = "ACME-001"
# title = "Internal debug endpoint enabled"
# severity = "medium"
# pattern = "enable_debug_endpoint\\\\s*=\\\\s*True"
# languages = ["Python"]
# context = "code"
# cwe = "CWE-489"
# owasp = "A05"
# description = "The internal debug endpoint exposes diagnostics that must never reach production."
# recommendation = "Remove the flag or drive it from an environment variable that defaults to False."
'''


@dataclass
class ProjectConfig:
    source: str | None = None
    exclude: list[str] = field(default_factory=list)
    min_confidence: str = "low"
    disable: list[str] = field(default_factory=list)
    severity: dict[str, str] = field(default_factory=dict)
    allow_paths: list[str] = field(default_factory=list)
    allow_values: list[re.Pattern] = field(default_factory=list)
    custom_rules: list[Rule] = field(default_factory=list)
    intel_private: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    # Provenance: which entries came from the audited repository (as opposed to the analyst's own configuration).
    ignored_source: str | None = None       # repository config found but NOT applied (untrusted target)
    repo_exclude: list[str] = field(default_factory=list)
    repo_disable: list[str] = field(default_factory=list)
    repo_severity: dict[str, str] = field(default_factory=dict)
    repo_allow_paths: list[str] = field(default_factory=list)
    repo_allow_values: list[re.Pattern] = field(default_factory=list)
    repo_min_confidence: bool = False

    def allowlisted(self, finding: dict) -> tuple[str, bool] | None:
        """Return (reason, comes_from_repository_config) when the finding is allow-listed."""
        path = finding.get("file") or ""
        where = os.path.basename(self.source or ".securerepo.toml")
        for pattern in self.allow_paths:
            if fnmatch.fnmatch(path, pattern):
                return f"path allow-listed in the project configuration ({pattern})", pattern in self.repo_allow_paths
        evidence = f"{finding.get('snippet', '')}\n{finding.get('detail', '')}"
        for regex in self.allow_values:
            if regex.search(evidence):
                return f"value allow-listed in the project configuration ({where})", regex in self.repo_allow_values
        return None


def is_within(path: str, root: str) -> bool:
    """True when ``path`` is ``root`` or lives inside it (a plain prefix test would also match /app-old for /app)."""
    try:
        return os.path.commonpath([os.path.abspath(path), os.path.abspath(root)]) == os.path.abspath(root)
    except ValueError:  # different drives on Windows
        return False


def _custom_rule(raw: dict, errors: list[str], origin: str) -> Rule | None:
    rule_id = str(raw.get("id", "")).strip()
    if not rule_id or not raw.get("pattern"):
        errors.append(f"{origin}: custom rule without 'id' or 'pattern' ignored")
        return None
    if rule_id in RULES_BY_ID:
        errors.append(f"{origin}: custom rule id {rule_id} collides with a built-in rule")
        return None
    severity = str(raw.get("severity", "medium")).lower()
    if severity not in SEVERITIES:
        errors.append(f"{origin}: {rule_id} has an invalid severity '{severity}'")
        return None
    for field_name in ("pattern", "exclude", "path"):
        if raw.get(field_name):
            risk = redos.check_pattern(str(raw[field_name]))
            if risk:
                errors.append(f"{origin}: custom rule {rule_id} rejected - '{field_name}' has {risk}")
                return None
    try:
        re.compile(raw["pattern"])
    except re.error as exc:
        errors.append(f"{origin}: {rule_id} has an invalid pattern ({exc})")
        return None
    context = str(raw.get("context", "strings")).lower()
    languages = tuple(raw.get("languages") or ["*"])
    return Rule(
        id=rule_id, title=str(raw.get("title", rule_id)), severity=severity,
        category=str(raw.get("category", "Custom")), cwe=str(raw.get("cwe", "")), owasp=str(raw.get("owasp", "OTHER")),
        description=str(raw.get("description", "Custom rule defined by the project.")),
        recommendation=str(raw.get("recommendation", "Review this finding according to the project guidelines.")),
        pattern=raw["pattern"], languages=languages, path=str(raw.get("path", "")), exclude=str(raw.get("exclude", "")),
        keywords=tuple(k.lower() for k in raw.get("keywords", [])), tags=tuple(raw.get("tags", ["custom"])),
        confidence=str(raw.get("confidence", "medium")), scan_comments=context == "raw",
        needs_strings=context in ("strings", "raw"), source="secret" if raw.get("secret") else "code",
        redact=bool(raw.get("secret")),
    )


def _read(path: str, errors: list[str]) -> dict:
    try:
        with open(path, "rb") as handle:
            return _toml.load(handle)
    except (OSError, ValueError) as exc:
        errors.append(f"{path}: {exc}")
        return {}


def load_config(root: str, user_dir: str | None = None, trust_repo: bool = True) -> ProjectConfig:
    """Load the analyst's configuration and, only when ``trust_repo`` is set, the one stored in the audited repo.

    A repository under audit is untrusted input: its own ``.securerepo.toml`` must not be able to disable rules,
    lower severities, exclude files or allow-list findings unless the analyst explicitly trusts it.
    """
    config = ProjectConfig()
    sources = []
    if user_dir:
        sources.append(os.path.join(user_dir, "config.toml"))
    repo_sources = [os.path.join(root, name) for name in CONFIG_NAMES]
    if trust_repo:
        sources += repo_sources
    else:
        config.ignored_source = next((p for p in repo_sources if os.path.isfile(p)), None)
    for path in sources:
        if not os.path.isfile(path):
            continue
        data = _read(path, config.errors)
        if not data:
            continue
        from_repo = is_within(path, root)
        if from_repo:
            config.source = path
        scan = data.get("scan", {}) or {}
        excluded = [str(p) for p in scan.get("exclude", [])]
        config.exclude += excluded
        level = str(scan.get("min_confidence", config.min_confidence)).lower()
        if level in CONFIDENCE_LEVELS:
            config.min_confidence = level
            config.repo_min_confidence = from_repo and level != "low"
        rules = data.get("rules", {}) or {}
        disabled = [canonical_rule_id(str(r)) for r in rules.get("disable", [])]
        config.disable += disabled
        overrides = {canonical_rule_id(str(k)): str(v).lower() for k, v in (rules.get("severity", {}) or {}).items()
                     if str(v).lower() in SEVERITIES}
        config.severity.update(overrides)
        intel_section = data.get("intel", {}) or {}
        config.intel_private += [str(p).strip() for p in intel_section.get("private", []) if str(p).strip()]
        allow = data.get("allowlist", {}) or {}
        allowed_paths = [str(p) for p in allow.get("paths", [])]
        config.allow_paths += allowed_paths
        if from_repo:
            config.repo_exclude += excluded
            config.repo_disable += disabled
            config.repo_severity.update(overrides)
            config.repo_allow_paths += allowed_paths
        for value in allow.get("values", []):
            risk = redos.check_pattern(str(value))
            if risk:
                config.errors.append(f"{path}: allowlist regex {str(value)[:60]!r} rejected - {risk}")
                continue
            try:
                compiled = re.compile(str(value))
            except re.error as exc:
                config.errors.append(f"{path}: invalid allowlist regex {value!r} ({exc})")
                continue
            config.allow_values.append(compiled)
            if from_repo:
                config.repo_allow_values.append(compiled)
        for raw in data.get("custom_rules", []) or []:
            rule = _custom_rule(raw, config.errors, os.path.basename(path))
            if rule:
                config.custom_rules.append(rule)
    return config


def write_template(directory: str) -> str:
    path = os.path.join(directory, CONFIG_NAMES[0])
    if os.path.exists(path):
        raise FileExistsError(path)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(TEMPLATE)
    return path
