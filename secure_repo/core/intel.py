"""Vulnerability intelligence: OSV.dev advisories, deps.dev metadata and CVSS scoring.

Only package names and versions are sent to these public services; source code
never leaves the machine. Offline mode disables every network request.
"""

from __future__ import annotations

import json
import math
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional, Tuple

from secure_repo import __version__
from secure_repo.core.events import EventBus
from secure_repo.core.models import Dependency

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"
DEPSDEV_URL = "https://api.deps.dev/v3/systems/"
OSV_ECOSYSTEMS = {"PyPI", "npm", "Go", "crates.io", "RubyGems", "Packagist", "Maven", "NuGet", "Pub", "Hex"}
DEPSDEV_SYSTEMS = {"PyPI": "pypi", "npm": "npm", "Go": "go", "crates.io": "cargo", "RubyGems": "rubygems",
                   "Maven": "maven", "NuGet": "nuget"}
USER_AGENT = f"secure-repo/{__version__} (+security audit tool)"

# Packages known to have been hijacked/sabotaged (name -> set of versions, empty = every version).
COMPROMISED = {
    "npm": {
        "event-stream": {"3.3.6"}, "flatmap-stream": set(), "ua-parser-js": {"0.7.29", "0.8.0", "1.0.0"},
        "coa": {"2.0.3", "2.0.4", "2.1.1", "2.1.3", "3.0.1", "3.1.3"}, "rc": {"1.2.9", "1.3.9", "2.3.9"},
        "node-ipc": {"10.1.1", "10.1.2"}, "colors": {"1.4.44-liberty-2"}, "faker": {"6.6.6"},
        "crossenv": set(),
    },
    "PyPI": {"jeilyfish": set(), "python3-dateutil": set(), "python-sqlite": set(), "urlib3": set(),
             "colourama": set()},
}
DEPRECATED = {
    "npm": {"request": "Use undici, node-fetch or axios.", "node-uuid": "Use uuid.",
            "crypto": "Use Node's built-in crypto module.", "querystring": "Use URLSearchParams.",
            "left-pad": "Use String.prototype.padStart.", "nomnom": "Use commander or yargs.",
            "istanbul": "Use nyc / c8.", "tslint": "Use ESLint with typescript-eslint.",
            "request-promise": "Use a maintained HTTP client."},
    "PyPI": {"pycrypto": "Use pycryptodome or cryptography.", "nose": "Use pytest.",
             "python-jose": "Consider pyjwt or joserfc (maintained).",
             "pyopenssl": "Prefer the cryptography package where possible."},
    "RubyGems": {"therubyracer": "Use mini_racer or execjs."},
}
COPYLEFT_RE = re.compile(r"(?i)\b(?:A?GPL|LGPL|SSPL|EUPL|OSL|CC-BY-SA|CPAL|RPL|MS-RL|Commons-Clause|BUSL)")


def _ssl_context() -> ssl.SSLContext:
    return ssl.create_default_context()


def _http_json(url: str, payload: Optional[Dict] = None, timeout: int = 20):
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(url, data=data, method="POST" if data else "GET", headers={
        "User-Agent": USER_AGENT, "Accept": "application/json", "Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout, context=_ssl_context()) as response:  # nosec - fixed https URLs
        return json.loads(response.read().decode("utf-8"))


# ---------------------------------------------------------------------------
# CVSS v3.x base score
# ---------------------------------------------------------------------------

def _roundup(value: float) -> float:
    integer = round(value * 100000)
    if integer % 10000 == 0:
        return integer / 100000.0
    return (math.floor(integer / 10000) + 1) / 10.0


def cvss3_score(vector: str) -> Optional[float]:
    try:
        metrics = dict(part.split(":", 1) for part in vector.split("/")[1:])
        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[metrics["AV"]]
        ac = {"L": 0.77, "H": 0.44}[metrics["AC"]]
        ui = {"N": 0.85, "R": 0.62}[metrics["UI"]]
        scope_changed = metrics["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if scope_changed else 0.62, "H": 0.5 if scope_changed else 0.27}[metrics["PR"]]
        cia = {"H": 0.56, "L": 0.22, "N": 0.0}
        iss = 1 - (1 - cia[metrics["C"]]) * (1 - cia[metrics["I"]]) * (1 - cia[metrics["A"]])
    except (KeyError, ValueError):
        return None
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed else 6.42 * iss
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    if scope_changed:
        return _roundup(min(1.08 * (impact + exploitability), 10))
    return _roundup(min(impact + exploitability, 10))


def score_to_severity(score: Optional[float]) -> str:
    if score is None:
        return "medium"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


_LABEL_SEVERITY = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium", "LOW": "low"}


def normalize_vulnerability(raw: Dict, package: str) -> Dict:
    vuln_id = raw.get("id", "")
    aliases = raw.get("aliases", []) or []
    score, vector = None, ""
    for entry in raw.get("severity", []) or []:
        if entry.get("type", "").startswith("CVSS_V3"):
            vector = entry.get("score", "")
            score = cvss3_score(vector)
        elif entry.get("type") == "CVSS_V4" and not vector:
            vector = entry.get("score", "")
    label = (raw.get("database_specific") or {}).get("severity")
    fixed: List[str] = []
    for affected in raw.get("affected", []) or []:
        pkg = (affected.get("package") or {}).get("name", "")
        if pkg.lower() != package.lower():
            continue
        label = label or (affected.get("database_specific") or {}).get("severity") or (
            affected.get("ecosystem_specific") or {}).get("severity")
        for rng in affected.get("ranges", []) or []:
            for event in rng.get("events", []) or []:
                if "fixed" in event and event["fixed"] not in fixed:
                    fixed.append(event["fixed"])
    if vuln_id.startswith("MAL-"):
        severity = "critical"
    elif isinstance(label, str) and label.upper() in _LABEL_SEVERITY:
        severity = _LABEL_SEVERITY[label.upper()]
    else:
        severity = score_to_severity(score)
    summary = raw.get("summary") or (raw.get("details") or "").strip().split("\n")[0]
    references = [ref.get("url") for ref in raw.get("references", []) or [] if ref.get("url")][:6]
    return {
        "id": vuln_id, "aliases": aliases, "summary": summary[:400], "severity": severity, "cvss": score,
        "vector": vector, "fixed": fixed[:6], "published": raw.get("published", ""),
        "references": references or [f"https://osv.dev/vulnerability/{vuln_id}"],
        "url": f"https://osv.dev/vulnerability/{vuln_id}",
    }


def osv_lookup(deps: List[Dependency], bus: EventBus, workers: int = 8) -> Tuple[int, int]:
    """Attach OSV advisories to dependencies. Returns (queried, vulnerable)."""
    candidates: Dict[Tuple[str, str, str], List[Dependency]] = {}
    for dep in deps:
        if dep.version and dep.source == "registry" and dep.ecosystem in OSV_ECOSYSTEMS:
            candidates.setdefault((dep.ecosystem, dep.name, dep.version), []).append(dep)
    keys = list(candidates)
    if not keys:
        bus.log("No resolvable dependency versions to query")
        return 0, 0
    bus.log(f"Querying OSV.dev for {len(keys)} unique package versions")
    ids_per_key: Dict[Tuple[str, str, str], List[str]] = {}
    for start in range(0, len(keys), 500):
        chunk = keys[start:start + 500]
        payload = {"queries": [{"package": {"name": n, "ecosystem": e}, "version": v} for e, n, v in chunk]}
        response = _http_json(OSV_BATCH_URL, payload, timeout=60)
        for key, result in zip(chunk, response.get("results", [])):
            ids = [v["id"] for v in (result or {}).get("vulns", []) or []]
            if ids:
                ids_per_key[key] = ids
        bus.progress("intel", min(start + 500, len(keys)), len(keys), "OSV batch query")
    unique_ids = sorted({vid for ids in ids_per_key.values() for vid in ids})
    bus.log(f"{len(unique_ids)} advisories matched - downloading details")
    details: Dict[str, Dict] = {}

    def fetch(vuln_id: str):
        try:
            return vuln_id, _http_json(OSV_VULN_URL + urllib.parse.quote(vuln_id), timeout=30)
        except (urllib.error.URLError, OSError, ValueError):
            return vuln_id, {"id": vuln_id, "summary": "Details unavailable (network error)."}

    with ThreadPoolExecutor(max_workers=workers) as pool:
        for index, (vuln_id, data) in enumerate(pool.map(fetch, unique_ids), 1):
            details[vuln_id] = data
            if index % 10 == 0 or index == len(unique_ids):
                bus.progress("intel", index, len(unique_ids), "Advisory details")
    vulnerable = 0
    for key, ids in ids_per_key.items():
        normalized = []
        seen_aliases = set()
        for vuln_id in ids:
            vuln = normalize_vulnerability(details.get(vuln_id, {"id": vuln_id}), key[1])
            identity = {vuln_id, *vuln["aliases"]}
            if identity & seen_aliases:
                continue
            seen_aliases |= identity
            normalized.append(vuln)
        for dep in candidates[key]:
            dep.vulnerabilities = normalized
        vulnerable += len(candidates[key])
    return len(keys), vulnerable


def depsdev_enrich(deps: List[Dependency], bus: EventBus, limit: int = 250, workers: int = 12) -> int:
    """Fetch license and latest-version metadata for direct dependencies."""
    targets = [d for d in deps if d.direct and d.source == "registry" and d.ecosystem in DEPSDEV_SYSTEMS][:limit]
    if not targets:
        return 0
    bus.log(f"Fetching license & release metadata for {len(targets)} direct libraries (deps.dev)")

    def enrich(dep: Dependency) -> bool:
        system = DEPSDEV_SYSTEMS[dep.ecosystem]
        base = DEPSDEV_URL + system + "/packages/" + urllib.parse.quote(dep.name, safe="")
        try:
            package = _http_json(base, timeout=15)
            for version in package.get("versions", []) or []:
                if version.get("isDefault"):
                    dep.latest = (version.get("versionKey") or {}).get("version")
            if dep.version:
                info = _http_json(base + "/versions/" + urllib.parse.quote(dep.version, safe=""), timeout=15)
                dep.licenses = [str(item) for item in info.get("licenses", []) or []]
            return True
        except (urllib.error.URLError, OSError, ValueError):
            return False

    done = 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for index, ok in enumerate(pool.map(enrich, targets), 1):
            done += int(ok)
            if index % 10 == 0 or index == len(targets):
                bus.progress("intel", index, len(targets), "Library metadata")
    return done


def major(version: Optional[str]) -> Optional[int]:
    if not version:
        return None
    match = re.match(r"^v?(\d+)", version)
    return int(match.group(1)) if match else None


def known_bad(dep: Dependency) -> Optional[Tuple[str, str]]:
    """Return (rule_id, detail) for compromised or deprecated packages."""
    name = dep.name.lower()
    versions = COMPROMISED.get(dep.ecosystem, {}).get(name)
    if versions is not None and (not versions or (dep.version in versions)):
        which = f"version {dep.version}" if versions else "every published version"
        return "SR-DEP-002", f"{dep.name} ({which}) is a known compromised/malicious package."
    hint = DEPRECATED.get(dep.ecosystem, {}).get(name)
    if hint and dep.direct:
        return "SR-DEP-003", f"{dep.name} is deprecated or unmaintained. {hint}"
    return None
