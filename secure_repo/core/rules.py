"""Detection signatures used by the static analyzer.

Every rule documents *why* the pattern is dangerous and *how* to fix it; that
text is surfaced in the CLI, in the GUI explanation panel and in the reports.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Pattern, Tuple

try:  # Python 3.11+
    import tomllib as _toml
except ModuleNotFoundError:  # pragma: no cover
    try:
        import tomli as _toml  # type: ignore
    except ModuleNotFoundError:
        _toml = None  # type: ignore

# ---------------------------------------------------------------------------
# Language groups
# ---------------------------------------------------------------------------
PY = ("Python",)
JS = ("JavaScript", "TypeScript", "Vue", "Svelte")
WEB = JS + ("HTML",)
JVM = ("Java", "Kotlin", "Scala", "Groovy")
CS = ("C#", "VB.NET", "F#")
PHP = ("PHP",)
GO = ("Go",)
RB = ("Ruby",)
CC = ("C", "C++", "Objective-C")
RS = ("Rust",)
SHELLISH = ("Shell", "Dockerfile", "YAML", "Makefile", "PowerShell", "Batch", "Groovy")
IAC = ("Terraform", "HCL", "JSON", "YAML")
CONFIG = ("Env", "INI", "Config", "Properties", "YAML", "TOML")
CODE = PY + JS + JVM + CS + PHP + GO + RB + CC + RS + ("Swift", "Dart", "Lua", "Perl", "Elixir", "Solidity")
ANY = ("*",)

WORKFLOW_PATH = r"(^|/)\.github/workflows/[^/]+\.ya?ml$"
CI_PATH = r"(^|/)(\.github/workflows/[^/]+\.ya?ml|\.gitlab-ci\.ya?ml|azure-pipelines\.ya?ml|bitbucket-pipelines\.ya?ml|\.circleci/config\.ya?ml|Jenkinsfile)$"


@dataclass
class RuleExample:
    """A snippet that documents and tests a rule: a positive must raise it, a negative must not."""
    kind: str                      # "positive" | "negative"
    code: str
    file: str = ""                 # file name used for the language and path rules (default: derived from the rule)
    scope: str = "file"            # "repo": scanned as a whole repository (hygiene, dependency and CI rules)
    extra: Dict[str, str] = field(default_factory=dict)   # additional files of the example repository
    online: bool = False           # needs OSV.dev / deps.dev: skipped unless the examples are run online


@dataclass
class Rule:
    id: str
    title: str
    severity: str
    category: str
    cwe: str
    owasp: str
    description: str
    recommendation: str
    pattern: str = ""
    languages: Tuple[str, ...] = ANY
    path: str = ""
    exclude: str = ""
    keywords: Tuple[str, ...] = ()
    tags: Tuple[str, ...] = ()
    confidence: str = "medium"
    scan_comments: bool = False
    redact: bool = False
    source: str = "code"
    references: Tuple[str, ...] = ()
    flags: int = 0
    needs_strings: bool = False  # the pattern must see string contents (URLs, algorithm names, '*'...)
    region: str = ""             # only report matches inside this structural region (see core/regions.py)
    examples: List[RuleExample] = field(default_factory=list, compare=False, repr=False)
    _regex: Optional[Pattern] = field(default=None, repr=False, compare=False)
    _path_re: Optional[Pattern] = field(default=None, repr=False, compare=False)
    _exclude_re: Optional[Pattern] = field(default=None, repr=False, compare=False)

    @property
    def regex(self) -> Optional[Pattern]:
        if self.pattern and self._regex is None:
            self._regex = re.compile(self.pattern, re.MULTILINE | self.flags)
        return self._regex

    @property
    def exclude_re(self) -> Optional[Pattern]:
        if self.exclude and self._exclude_re is None:
            self._exclude_re = re.compile(self.exclude)
        return self._exclude_re

    @property
    def view(self) -> str:
        """Which lexical view the pattern runs on: raw text, comments masked, or comments+strings masked."""
        if self.source == "secret" or self.scan_comments:
            return "raw"
        return "strings" if self.needs_strings else "code"

    def applies_to(self, language: str, rel_path: str) -> bool:
        if self.path:
            if self._path_re is None:
                self._path_re = re.compile(self.path, re.IGNORECASE)
            if not self._path_re.search(rel_path):
                return False
        return "*" in self.languages or language in self.languages

    def reference_links(self) -> List[str]:
        links = list(self.references)
        if self.cwe.startswith("CWE-"):
            links.insert(0, f"https://cwe.mitre.org/data/definitions/{self.cwe[4:]}.html")
        if self.owasp and self.owasp.startswith("A"):
            links.append(f"https://owasp.org/Top10/{OWASP_SLUGS.get(self.owasp, '')}")
        return links

    def to_dict(self) -> Dict:
        return {
            "id": self.id, "title": self.title, "severity": self.severity, "category": self.category,
            "cwe": self.cwe, "owasp": self.owasp, "description": self.description,
            "recommendation": self.recommendation, "tags": list(self.tags),
            "confidence": self.confidence, "references": self.reference_links(),
            "languages": list(self.languages), "source": self.source,
        }


OWASP_SLUGS = {
    "A01": "A01_2021-Broken_Access_Control/", "A02": "A02_2021-Cryptographic_Failures/",
    "A03": "A03_2021-Injection/", "A04": "A04_2021-Insecure_Design/",
    "A05": "A05_2021-Security_Misconfiguration/", "A06": "A06_2021-Vulnerable_and_Outdated_Components/",
    "A07": "A07_2021-Identification_and_Authentication_Failures/",
    "A08": "A08_2021-Software_and_Data_Integrity_Failures/",
    "A09": "A09_2021-Security_Logging_and_Monitoring_Failures/",
    "A10": "A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
}

# ---------------------------------------------------------------------------
# Rules live in data files (secure_repo/ruledata/<prefix>.toml), not in code: reviewing, testing and contributing a
# rule means editing a table with its pattern and its positive / negative examples.
# ---------------------------------------------------------------------------
RULE_DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ruledata")
_FLAG_NAMES = {"IGNORECASE": re.IGNORECASE, "DOTALL": re.DOTALL, "MULTILINE": re.MULTILINE, "VERBOSE": re.VERBOSE}
_LANGUAGE_GROUPS = {"CODE": CODE, "PY": PY, "JS": JS, "WEB": WEB, "JVM": JVM, "CS": CS, "PHP": PHP, "GO": GO, "RB": RB,
                    "CC": CC, "RS": RS, "SHELLISH": SHELLISH, "IAC": IAC, "CONFIG": CONFIG}
_RULE_KEYS = {"id", "title", "severity", "category", "cwe", "owasp", "description", "recommendation", "pattern",
              "languages", "path", "exclude", "keywords", "tags", "confidence", "scan_comments", "redact", "source",
              "references", "flags", "needs_strings", "region", "example"}
_REQUIRED_KEYS = ("id", "title", "severity", "category", "description", "recommendation")
_SEVERITIES = ("critical", "high", "medium", "low", "info")


class RuleDataError(ValueError):
    """A rule data file is malformed (the message names the file and the rule)."""


def _languages(values: List[str], where: str) -> Tuple[str, ...]:
    expanded: List[str] = []
    for value in values:
        if value.startswith("@"):
            if value[1:] not in _LANGUAGE_GROUPS:
                raise RuleDataError(f"{where}: unknown language group {value}")
            expanded.extend(_LANGUAGE_GROUPS[value[1:]])
        else:
            expanded.append(value)
    return tuple(dict.fromkeys(expanded))


def _rule_from_table(table: Dict, origin: str) -> Rule:
    where = f"{origin}: rule {table.get('id', '?')}"
    unknown = set(table) - _RULE_KEYS
    if unknown:
        raise RuleDataError(f"{where}: unknown key(s) {sorted(unknown)}")
    for key in _REQUIRED_KEYS:
        if not table.get(key):
            raise RuleDataError(f"{where}: missing '{key}'")
    if table["severity"] not in _SEVERITIES:
        raise RuleDataError(f"{where}: invalid severity {table['severity']!r}")
    flags = 0
    for name in table.get("flags", []):
        if name not in _FLAG_NAMES:
            raise RuleDataError(f"{where}: unknown regex flag {name!r}")
        flags |= _FLAG_NAMES[name]
    examples = []
    for raw in table.get("example", []):
        if raw.get("kind") not in ("positive", "negative") or "code" not in raw:
            raise RuleDataError(f"{where}: an example needs kind = positive|negative and code")
        examples.append(RuleExample(kind=raw["kind"], code=raw["code"], file=raw.get("file", ""),
                                    scope=raw.get("scope", "file"), extra=dict(raw.get("extra", {})),
                                    online=bool(raw.get("online", False))))
    rule = Rule(
        id=table["id"], title=table["title"], severity=table["severity"], category=table["category"],
        cwe=table.get("cwe", ""), owasp=table.get("owasp", ""), description=table["description"],
        recommendation=table["recommendation"], pattern=table.get("pattern", ""),
        languages=_languages(table.get("languages", ["*"]), where), path=table.get("path", ""),
        exclude=table.get("exclude", ""), keywords=tuple(table.get("keywords", ())), tags=tuple(table.get("tags", ())),
        confidence=table.get("confidence", "medium"), scan_comments=bool(table.get("scan_comments", False)),
        redact=bool(table.get("redact", False)), source=table.get("source", "code"),
        references=tuple(table.get("references", ())), flags=flags, needs_strings=bool(table.get("needs_strings", False)),
        region=table.get("region", ""), examples=examples)
    if rule.pattern:
        try:
            re.compile(rule.pattern, re.MULTILINE | rule.flags)
        except re.error as exc:
            raise RuleDataError(f"{where}: invalid pattern ({exc})") from exc
    return rule


def load_rules(directory: str = RULE_DATA_DIR) -> List[Rule]:
    """Read every ``*.toml`` file of the rule data directory; rules are ordered by ID."""
    if _toml is None:  # pragma: no cover - Python < 3.11 without tomli
        raise RuleDataError("TOML support is missing: install 'tomli' (pip install tomli)")
    loaded: List[Rule] = []
    for name in sorted(os.listdir(directory)):
        if not name.endswith(".toml"):
            continue
        with open(os.path.join(directory, name), "rb") as handle:
            try:
                document = _toml.load(handle)
            except Exception as exc:
                raise RuleDataError(f"{name}: not valid TOML ({exc})") from exc
        for table in document.get("rule", []):
            loaded.append(_rule_from_table(table, name))
    identifiers = [rule.id for rule in loaded]
    duplicates = sorted({i for i in identifiers if identifiers.count(i) > 1})
    if duplicates:
        raise RuleDataError(f"duplicate rule IDs: {duplicates}")
    return sorted(loaded, key=lambda rule: rule.id)


RULES: List[Rule] = load_rules()

# Rules whose ID used to carry a language prefix that did not match where they apply (the JWT rule was "SR-JS-021"
# but fired on Python too). Old IDs keep working everywhere a user wrote one: .securerepo.toml, nosec comments, the
# triage knowledge base and shared triage files. Fingerprints keep using the legacy ID, so past decisions still match.
RULE_ALIASES: Dict[str, str] = {
    "SR-JS-010": "SR-GEN-008", "SR-JS-019": "SR-GEN-009", "SR-JS-020": "SR-GEN-010", "SR-JS-021": "SR-GEN-011",
    "SR-JAVA-002": "SR-GEN-012", "SR-JAVA-007": "SR-GEN-013",
}
LEGACY_IDS: Dict[str, str] = {new: old for old, new in RULE_ALIASES.items()}


def canonical_rule_id(rule_id: str) -> str:
    rule_id = (rule_id or "").strip()
    return RULE_ALIASES.get(rule_id, rule_id)


RULES_BY_ID: Dict[str, Rule] = {rule.id: rule for rule in RULES}
PATTERN_RULES: List[Rule] = [rule for rule in RULES if rule.pattern]
TOKEN_RULES: List[Rule] = [rule for rule in PATTERN_RULES if rule.source == "secret" and rule.redact]


def get_rule(rule_id: str) -> Rule:
    return RULES_BY_ID[rule_id]
