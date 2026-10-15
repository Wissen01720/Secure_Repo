"""Vulnerability intelligence: OSV.dev advisories, deps.dev metadata and CVSS scoring.

Only package names and versions are sent to these public services; source code
never leaves the machine. Offline mode disables every network request.
"""

from __future__ import annotations

import json
import math
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional, Tuple

from secure_repo.core import netio
from secure_repo.core.events import EventBus
from secure_repo.core.models import Dependency

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"
DEPSDEV_URL = "https://api.deps.dev/v3/systems/"
OSV_ECOSYSTEMS = {"PyPI", "npm", "Go", "crates.io", "RubyGems", "Packagist", "Maven", "NuGet", "Pub", "Hex"}
DEPSDEV_SYSTEMS = {"PyPI": "pypi", "npm": "npm", "Go": "go", "crates.io": "cargo", "RubyGems": "rubygems",
                   "Maven": "maven", "NuGet": "nuget"}
USER_AGENT = netio.USER_AGENT

PACKAGE_DATA_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "packages.json")


def load_package_data(path: str = PACKAGE_DATA_FILE) -> Dict:
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


# Fallback lists (the OSV malicious-package advisories, MAL-*, take precedence): see data/packages.json for the
# source and date of every entry.
PACKAGE_DATA = load_package_data()
COMPROMISED: Dict[str, Dict[str, set]] = {
    ecosystem: {name: set(entry.get("versions", [])) for name, entry in names.items()}
    for ecosystem, names in PACKAGE_DATA["compromised"].items()}
DEPRECATED: Dict[str, Dict[str, str]] = {
    ecosystem: {name: entry["hint"] for name, entry in names.items()}
    for ecosystem, names in PACKAGE_DATA["deprecated"].items()}
MAX_OSV_PAGES = 10
OSV_CHUNK = 500
COPYLEFT_RE = re.compile(r"(?i)\b(?:A?GPL|LGPL|SSPL|EUPL|OSL|CC-BY-SA|CPAL|RPL|MS-RL|Commons-Clause|BUSL)")


def _http_json(url: str, payload: Optional[Dict] = None, timeout: int = 20, cache: bool = False):
    """JSON over HTTPS with size limits, retries, disk cache and CA selection (see core/netio.py)."""
    return netio.http_json(url, payload, timeout=timeout, cache=cache)


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


def _osv_query(keys: List[Tuple[str, str, str]]) -> Dict[Tuple[str, str, str], List[str]]:
    """Advisory IDs of every (ecosystem, name, version), following OSV's ``next_page_token`` pagination.

    A batch that keeps failing (after the retries of netio) is recorded as a note and the other batches carry on;
    only when *every* batch fails is the error raised, so the caller can report that the intelligence is missing.
    """
    found: Dict[Tuple[str, str, str], List[str]] = {}
    failed, first_error, truncated = 0, None, 0
    chunks = [keys[start:start + OSV_CHUNK] for start in range(0, len(keys), OSV_CHUNK)]
    for number, chunk in enumerate(chunks, 1):
        pending: List[Tuple[Tuple[str, str, str], Optional[str]]] = [(key, None) for key in chunk]
        pages = 0
        try:
            while pending and pages < MAX_OSV_PAGES:
                queries = []
                for (ecosystem, name, version), token in pending:
                    query = {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
                    if token:
                        query["page_token"] = token
                    queries.append(query)
                response = _http_json(OSV_BATCH_URL, {"queries": queries}, timeout=60)
                following: List[Tuple[Tuple[str, str, str], Optional[str]]] = []
                for (key, _token), result in zip(pending, response.get("results", [])):
                    result = result or {}
                    for vuln in result.get("vulns", []) or []:
                        ids = found.setdefault(key, [])
                        if vuln["id"] not in ids:
                            ids.append(vuln["id"])
                    if result.get("next_page_token"):
                        following.append((key, result["next_page_token"]))
                pending, pages = following, pages + 1
            truncated += len(pending)
        except (urllib.error.URLError, OSError, ValueError) as exc:
            failed += 1
            first_error = first_error or exc
            netio.note(f"OSV.dev batch {number} of {len(chunks)} failed ({getattr(exc, 'reason', exc)}): "
                       f"{len(chunk)} package versions were not checked for vulnerabilities")
    if keys and failed == len(chunks) and first_error is not None:
        raise first_error
    if truncated:
        netio.note(f"{truncated} package version(s) have more advisories than the {MAX_OSV_PAGES} result pages "
                   "that were downloaded")
    return found


def osv_lookup(deps: List[Dependency], bus: EventBus, workers: int = 8) -> Tuple[int, int]:
    """Attach OSV advisories to dependencies. Returns (queried, vulnerable)."""
    candidates: Dict[Tuple[str, str, str], List[Dependency]] = {}
    for dep in deps:
        if dep.version and dep.source == "registry" and dep.ecosystem in OSV_ECOSYSTEMS and not dep.private:
            candidates.setdefault((dep.ecosystem, dep.name, dep.version), []).append(dep)
    keys = list(candidates)
    if not keys:
        bus.log("No resolvable dependency versions to query")
        return 0, 0
    bus.log(f"Querying OSV.dev for {len(keys)} unique package versions")
    ids_per_key = _osv_query(keys)
    bus.progress("intel", len(keys), len(keys), "OSV batch query")
    unique_ids = sorted({vid for ids in ids_per_key.values() for vid in ids})
    bus.log(f"{len(unique_ids)} advisories matched - downloading details")
    details: Dict[str, Dict] = {}

    def fetch(vuln_id: str):
        try:
            return vuln_id, _http_json(OSV_VULN_URL + urllib.parse.quote(vuln_id), timeout=30, cache=True)
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
        seen_aliases: set = set()
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


def osv_vulnerability_ids(keys: List[Tuple[str, str, str]]) -> Dict[Tuple[str, str, str], List[str]]:
    """Advisory IDs affecting each (ecosystem, name, version) - no details downloaded."""
    return _osv_query([k for k in keys if k[0] in OSV_ECOSYSTEMS])


def depsdev_enrich(deps: List[Dependency], bus: EventBus, limit: int = 250, workers: int = 12) -> int:
    """Fetch license and latest-version metadata for direct dependencies."""
    eligible = [d for d in deps if d.direct and d.source == "registry" and d.ecosystem in DEPSDEV_SYSTEMS
                and not d.private]
    targets = eligible[:limit]
    if len(eligible) > len(targets):
        netio.note(f"{len(eligible) - len(targets)} direct librar{'y' if len(eligible) - len(targets) == 1 else 'ies'} "
                   f"got no license / latest-version lookup because of the limit ({limit}); raise it with --max-enrich")
    if not targets:
        return 0
    bus.log(f"Fetching license & release metadata for {len(targets)} direct libraries (deps.dev)")

    def enrich(dep: Dependency) -> bool:
        system = DEPSDEV_SYSTEMS[dep.ecosystem]
        base = DEPSDEV_URL + system + "/packages/" + urllib.parse.quote(dep.name, safe="")
        try:
            package = _http_json(base, timeout=15, cache=True)
            for version in package.get("versions", []) or []:
                if version.get("isDefault"):
                    dep.latest = (version.get("versionKey") or {}).get("version")
            if dep.version:
                info = _http_json(base + "/versions/" + urllib.parse.quote(dep.version, safe=""), timeout=15, cache=True)
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


def exists_publicly(dep: Dependency) -> Optional[bool]:
    """Does a package with this name exist in the public registry? (None = could not tell). Sends the name."""
    system = DEPSDEV_SYSTEMS.get(dep.ecosystem)
    if not system:
        return None
    name = dep.name.lower() if dep.ecosystem == "PyPI" else dep.name
    try:
        _http_json(DEPSDEV_URL + system + "/packages/" + urllib.parse.quote(name, safe=""), timeout=15, cache=True)
        return True
    except urllib.error.HTTPError as exc:
        return False if exc.code == 404 else None
    except (urllib.error.URLError, OSError, ValueError):
        return None


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
