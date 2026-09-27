"""Version resolution for projects without lockfiles ("virtual lockfile").

Resolution order for every dependency declared with a range:

1. **lockfile**    - already handled by the manifest parsers;
2. **environment** - versions actually installed next to the project (``node_modules``,
   virtualenvs, ``vendor/composer/installed.json``, bundler ``vendor/bundle``). Works offline;
3. **registry**    - the version the package manager would install *today* for the declared
   range, computed from the registry's release list (deps.dev, Packagist, pub.dev);
4. **graph**       - transitive dependencies of the resolved direct libraries (deps.dev
   dependency graph for npm, Cargo, Maven and PyPI).

Only package names and versions are sent to public registries. Nothing is installed or executed.
"""

from __future__ import annotations

import glob
import json
import os
import re
import urllib.error
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional, Tuple

from secure_repo.core import versions as vmod
from secure_repo.core.deps import normalize_name
from secure_repo.core.events import EventBus
from secure_repo.core.intel import DEPSDEV_SYSTEMS, DEPSDEV_URL, _http_json
from secure_repo.core.models import Dependency

GRAPH_SYSTEMS = {"npm", "crates.io", "Maven", "PyPI"}
MAX_REGISTRY = 300
MAX_GRAPH = 120

LOCK_COMMANDS = {
    "PyPI": ["pip-compile --generate-hashes requirements.in   (pip-tools)", "uv pip compile requirements.in -o requirements.txt",
             "poetry lock", "pipenv lock"],
    "npm": ["npm install --package-lock-only --ignore-scripts", "yarn install --mode=update-lockfile", "pnpm install --lockfile-only"],
    "crates.io": ["cargo generate-lockfile"],
    "RubyGems": ["bundle lock"],
    "Packagist": ["composer update --no-install --no-scripts"],
    "Pub": ["dart pub get   (creates pubspec.lock)"],
    "NuGet": ["dotnet restore --use-lock-file   (creates packages.lock.json)"],
    "Maven": ["Pin exact versions in <dependencyManagement>", "./gradlew dependencies --write-locks   (Gradle)"],
}


# ---------------------------------------------------------------------- environment
def _python_environment(root: str) -> Dict[str, str]:
    installed: Dict[str, str] = {}
    for env in (".venv", "venv", "env", ".env", ".tox"):
        base = os.path.join(root, env)
        if not os.path.isdir(base):
            continue
        for pattern in ("Lib/site-packages/*.dist-info", "lib/python*/site-packages/*.dist-info",
                        "lib64/python*/site-packages/*.dist-info"):
            for info in glob.glob(os.path.join(base, pattern)):
                name, _, version = os.path.basename(info)[:-len(".dist-info")].rpartition("-")
                if name and version:
                    installed[normalize_name("PyPI", name)] = version
    return installed


def _read_json(path: str):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return None


def _composer_environment(directory: str) -> Dict[str, str]:
    data = _read_json(os.path.join(directory, "vendor", "composer", "installed.json"))
    packages = data.get("packages", []) if isinstance(data, dict) else (data or [])
    return {p["name"].lower(): str(p.get("version", "")).lstrip("v") for p in packages if isinstance(p, dict) and p.get("name")}


def _gem_environment(directory: str) -> Dict[str, str]:
    installed: Dict[str, str] = {}
    for spec in glob.glob(os.path.join(directory, "vendor", "bundle", "ruby", "*", "specifications", "*.gemspec")):
        name, _, version = os.path.basename(spec)[:-len(".gemspec")].rpartition("-")
        if name:
            installed[name.lower()] = version
    return installed


def resolve_from_environment(deps: List[Dependency], root: str) -> int:
    python_env: Optional[Dict[str, str]] = None
    cache: Dict[Tuple[str, str], Dict[str, str]] = {}
    count = 0
    for dep in deps:
        if dep.version or dep.source != "registry":
            continue
        directory = os.path.join(root, *os.path.dirname(dep.manifest).split("/")) if dep.manifest else root
        version = None
        if dep.ecosystem == "npm":
            package_json = os.path.join(directory, "node_modules", *dep.name.split("/"), "package.json")
            data = _read_json(package_json) if os.path.isfile(package_json) else None
            version = data.get("version") if isinstance(data, dict) else None
        elif dep.ecosystem == "PyPI":
            if python_env is None:
                python_env = _python_environment(root)
            version = python_env.get(normalize_name("PyPI", dep.name))
        elif dep.ecosystem in ("Packagist", "RubyGems"):
            key = (dep.ecosystem, directory)
            if key not in cache:
                cache[key] = _composer_environment(directory) if dep.ecosystem == "Packagist" else _gem_environment(directory)
            version = cache[key].get(dep.name.lower())
        if version:
            dep.version, dep.resolved_by = version, "environment"
            count += 1
    return count


# ---------------------------------------------------------------------- registry
def registry_versions(ecosystem: str, name: str) -> List[str]:
    if ecosystem in DEPSDEV_SYSTEMS:
        lookup = normalize_name("PyPI", name) if ecosystem == "PyPI" else name
        data = _http_json(DEPSDEV_URL + DEPSDEV_SYSTEMS[ecosystem] + "/packages/" + urllib.parse.quote(lookup, safe=""),
                          timeout=20)
        return [(v.get("versionKey") or {}).get("version", "") for v in data.get("versions", []) or []]
    if ecosystem == "Packagist":
        data = _http_json("https://repo.packagist.org/p2/" + urllib.parse.quote(name.lower(), safe="/") + ".json", timeout=20)
        releases = (data.get("packages") or {}).get(name.lower(), [])
        return [str(r.get("version", "")).lstrip("v") for r in releases if not str(r.get("version", "")).startswith("dev-")]
    if ecosystem == "Pub":
        data = _http_json("https://pub.dev/api/packages/" + urllib.parse.quote(name, safe=""), timeout=20)
        return [v.get("version", "") for v in data.get("versions", []) or []]
    return []


def _spec_for_resolution(dep: Dependency) -> str:
    spec = (dep.spec or "").strip()
    if dep.ecosystem == "PyPI":
        return spec.replace(" ", "") if spec not in ("", "*") else "*"
    if dep.ecosystem == "npm" and spec.startswith("npm:"):
        return spec.rsplit("@", 1)[-1]
    return spec or "*"


def resolve_from_registry(deps: List[Dependency], bus: EventBus, workers: int = 12) -> int:
    targets = [d for d in deps if not d.version and d.source == "registry" and d.direct and d.spec != "managed"][:MAX_REGISTRY]
    if not targets:
        return 0
    bus.log(f"Resolving {len(targets)} version range(s) against the package registries")

    def work(dep: Dependency) -> bool:
        try:
            available = registry_versions(dep.ecosystem, dep.name)
        except (urllib.error.URLError, OSError, ValueError):
            return False
        chosen, lowest = vmod.resolve(_spec_for_resolution(dep), available, dep.ecosystem)
        if chosen:
            dep.version, dep.resolved_by, dep.range_lowest = chosen, "registry", lowest
            return True
        return False

    resolved = 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for index, ok in enumerate(pool.map(work, targets), 1):
            resolved += int(ok)
            if index % 10 == 0 or index == len(targets):
                bus.progress("resolve", index, len(targets), "Registry resolution")
    return resolved


def resolve_graph(deps: List[Dependency], bus: EventBus, workers: int = 8) -> List[Dependency]:
    """Expand transitive dependencies of registry-resolved direct libraries (no lockfile available)."""
    roots = [d for d in deps if d.direct and d.version and d.resolved_by in ("registry", "environment", "manifest")
             and not d.locked and d.ecosystem in GRAPH_SYSTEMS][:MAX_GRAPH]
    if not roots:
        return []
    bus.log(f"Building the virtual dependency graph for {len(roots)} direct librar{'y' if len(roots) == 1 else 'ies'}")

    def work(dep: Dependency) -> List[Tuple[str, str]]:
        name = normalize_name("PyPI", dep.name) if dep.ecosystem == "PyPI" else dep.name
        url = (DEPSDEV_URL + DEPSDEV_SYSTEMS[dep.ecosystem] + "/packages/" + urllib.parse.quote(name, safe="") +
               "/versions/" + urllib.parse.quote(dep.version or "", safe="") + ":dependencies")
        try:
            data = _http_json(url, timeout=25)
        except (urllib.error.URLError, OSError, ValueError):
            return []
        found = []
        for node in data.get("nodes", []) or []:
            if node.get("relation") == "SELF":
                continue
            key = node.get("versionKey") or {}
            if key.get("name") and key.get("version"):
                found.append((key["name"], key["version"]))
        return found

    existing = {(d.ecosystem, normalize_name(d.ecosystem, d.name), d.version) for d in deps}
    added: List[Dependency] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for index, (root, nodes) in enumerate(zip(roots, pool.map(work, roots)), 1):
            for name, version in nodes:
                identity = (root.ecosystem, normalize_name(root.ecosystem, name), version)
                if identity in existing:
                    continue
                existing.add(identity)
                added.append(Dependency(name=name, ecosystem=root.ecosystem, version=version, spec=version,
                                        manifest=root.manifest, direct=False, scope=root.scope,
                                        manifests=[root.manifest], resolved_by="registry-graph", parent=root.name))
            if index % 10 == 0 or index == len(roots):
                bus.progress("resolve", index, len(roots), "Dependency graph")
    return added


# ---------------------------------------------------------------------- virtual lockfile
def virtual_lockfile(deps: List[Dependency]) -> Dict:
    """Machine-readable lock proposal + guidance, grouped by manifest."""
    manifests: Dict[str, Dict] = {}
    for dep in deps:
        if dep.resolved_by not in ("environment", "registry", "registry-graph"):
            continue
        entry = manifests.setdefault(dep.manifest, {"manifest": dep.manifest, "ecosystem": dep.ecosystem,
                                                     "commands": LOCK_COMMANDS.get(dep.ecosystem, []), "packages": []})
        entry["packages"].append({
            "name": dep.name, "declared": dep.spec if dep.direct else f"(via {dep.parent})", "resolved": dep.version,
            "resolved_by": dep.resolved_by, "direct": dep.direct, "range_lowest": dep.range_lowest,
            "vulnerable": bool(dep.vulnerabilities),
        })
    for entry in manifests.values():
        entry["packages"].sort(key=lambda p: (not p["direct"], p["name"].lower()))
    unresolved = [{"name": d.name, "ecosystem": d.ecosystem, "declared": d.spec, "manifest": d.manifest}
                  for d in deps if d.direct and not d.version and d.source == "registry" and d.spec != "managed"]
    return {"manifests": list(manifests.values()), "unresolved": unresolved}


def pinned_snippet(entry: Dict) -> str:
    direct = [p for p in entry["packages"] if p["direct"]]
    ecosystem = entry["ecosystem"]
    if ecosystem == "PyPI":
        return "\n".join(f"{p['name']}=={p['resolved']}" for p in direct)
    if ecosystem == "npm":
        body = ",\n".join(f'    "{p["name"]}": "{p["resolved"]}"' for p in direct)
        return '"dependencies": {\n' + body + "\n}"
    if ecosystem == "crates.io":
        return "\n".join(f'{p["name"]} = "={p["resolved"]}"' for p in direct)
    if ecosystem == "RubyGems":
        return "\n".join(f"gem '{p['name']}', '{p['resolved']}'" for p in direct)
    if ecosystem == "Packagist":
        return "\n".join(f'"{p["name"]}": "{p["resolved"]}",' for p in direct)
    if ecosystem == "Pub":
        return "\n".join(f"  {p['name']}: {p['resolved']}" for p in direct)
    if ecosystem == "NuGet":
        return "\n".join(f'<PackageReference Include="{p["name"]}" Version="[{p["resolved"]}]" />' for p in direct)
    if ecosystem == "Maven":
        return "\n".join(f"{p['name']}:{p['resolved']}" for p in direct)
    return "\n".join(f"{p['name']} {p['resolved']}" for p in direct)


def summarize(deps: List[Dependency]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for dep in deps:
        key = dep.resolved_by or ("unresolved" if dep.source == "registry" else dep.source)
        counts[key] = counts.get(key, 0) + 1
    return counts


def exact_or_none(spec: str) -> bool:
    return bool(re.fullmatch(r"=?=?\s*v?\d[\w.\-+]*", (spec or "").strip()))
