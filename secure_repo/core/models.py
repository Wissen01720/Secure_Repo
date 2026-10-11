"""Shared data models and security taxonomies."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITIES)}  # 0 = most severe
SEVERITY_WEIGHT = {"critical": 15.0, "high": 7.0, "medium": 3.0, "low": 1.0, "info": 0.0}

SEVERITY_DESCRIPTIONS = {
    "critical": "Directly exploitable weakness or exposed credential. Remediate immediately.",
    "high": "Serious weakness that is likely exploitable. Remediate before the next release.",
    "medium": "Weakness that requires specific conditions to be exploited. Plan remediation.",
    "low": "Defense-in-depth issue or hardening opportunity.",
    "info": "Informational observation that supports security governance.",
}

OWASP_TOP10: Dict[str, Dict[str, str]] = {
    "A01": {
        "name": "Broken Access Control",
        "description": "Restrictions on what authenticated users are allowed to do are not properly "
        "enforced, allowing unauthorized information disclosure, modification or destruction.",
    },
    "A02": {
        "name": "Cryptographic Failures",
        "description": "Failures related to cryptography (or its absence) that expose sensitive data, "
        "such as weak algorithms, cleartext transmission or poor key management.",
    },
    "A03": {
        "name": "Injection",
        "description": "User-supplied data is interpreted as code or commands (SQL, OS, template, "
        "expression or script injection, including Cross-Site Scripting).",
    },
    "A04": {
        "name": "Insecure Design",
        "description": "Missing or ineffective security controls at the design level, such as unsafe "
        "storage decisions or absent security processes.",
    },
    "A05": {
        "name": "Security Misconfiguration",
        "description": "Insecure default settings, verbose errors, debug modes, permissive CORS or "
        "over-privileged containers and infrastructure.",
    },
    "A06": {
        "name": "Vulnerable and Outdated Components",
        "description": "Use of libraries, frameworks or other components with known vulnerabilities "
        "or that are unsupported and out of date.",
    },
    "A07": {
        "name": "Identification and Authentication Failures",
        "description": "Weaknesses in authentication, session management and credential handling, "
        "including hardcoded credentials and disabled certificate validation.",
    },
    "A08": {
        "name": "Software and Data Integrity Failures",
        "description": "Code and infrastructure that does not protect against integrity violations: "
        "insecure deserialization, untrusted update channels and unverified supply chain.",
    },
    "A09": {
        "name": "Security Logging and Monitoring Failures",
        "description": "Insufficient logging, or logging that leaks sensitive data, preventing "
        "detection of and response to active breaches.",
    },
    "A10": {
        "name": "Server-Side Request Forgery",
        "description": "The application fetches a remote resource using a user-supplied URL "
        "without validation, letting attackers reach internal systems.",
    },
    "OTHER": {
        "name": "Other / CWE Top 25",
        "description": "Weaknesses outside the OWASP Top 10 web categories, such as memory-safety "
        "issues in native code, license or governance observations.",
    },
}


def owasp_key(code: str) -> str:
    return code if code in OWASP_TOP10 else "OTHER"


def worst_severity(severities) -> Optional[str]:
    best = None
    for sev in severities:
        if sev not in SEVERITY_RANK:
            continue
        if best is None or SEVERITY_RANK[sev] < SEVERITY_RANK[best]:
            best = sev
    return best


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    category: str
    file: str
    line: int = 0
    snippet: str = ""
    detail: str = ""
    cwe: str = ""
    owasp: str = ""
    tags: List[str] = field(default_factory=list)
    confidence: str = "medium"
    source: str = "code"
    in_test: bool = False
    id: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)
    # Analysis quality metadata ------------------------------------------------
    engine: str = "pattern"          # pattern | lexical | ast | taint | dependency | hygiene | custom
    flow: List[Dict[str, Any]] = field(default_factory=list)   # data-flow trace: source -> ... -> sink
    confidence_score: int = 0        # 0-100, computed by the confidence model
    fingerprint: str = ""            # stable identity used by triage (survives line shifts)
    status: str = "open"             # open | confirmed | accepted_risk | false_positive | filtered
    triage: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# Statuses that still represent risk (counted in the score and the compliance audit).
ACTIVE_STATUSES = ("open", "confirmed", "accepted_risk")
# Findings in these statuses are kept in the report (audit trail) but never affect the score or compliance.
SUPPRESSED_STATUSES = ("false_positive", "filtered", "disabled_by_config", "suppressed_inline")
# Triage origins that come from content controlled by the audited repository (not by the analyst).
REPO_CONTROLLED_ORIGINS = ("config", "repo-decision", "repo-pattern", "inline")
TRIAGE_STATUSES = ("open", "confirmed", "accepted_risk", "false_positive")


@dataclass
class Dependency:
    name: str
    ecosystem: str
    version: Optional[str]
    spec: str
    manifest: str
    direct: bool = True
    scope: str = "runtime"
    source: str = "registry"
    line: int = 0
    manifests: List[str] = field(default_factory=list)
    locked: bool = False
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    licenses: List[str] = field(default_factory=list)
    latest: Optional[str] = None
    issues: List[str] = field(default_factory=list)
    # How the concrete version was obtained: manifest | lockfile | environment | registry | registry-graph
    resolved_by: Optional[str] = None
    range_lowest: Optional[str] = None   # lowest version admitted by the declared range (registry resolution)
    parent: Optional[str] = None         # direct dependency that pulls this one in (virtual graph)

    @property
    def key(self) -> str:
        return f"{self.ecosystem}:{self.name}@{self.version or self.spec or '*'}"

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["key"] = self.key
        data["max_severity"] = worst_severity(v.get("severity") for v in self.vulnerabilities)
        return data
