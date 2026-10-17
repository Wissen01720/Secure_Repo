"""Dependency manifest and lockfile parsers for the most common ecosystems.

Every parser is defensive: malformed files never abort the scan, and XML is
parsed with defusedxml, after DOCTYPE declarations are stripped, to avoid entity-expansion attacks.
"""

from __future__ import annotations

import configparser
import json
import os
import re
from collections.abc import Callable

import defusedxml.ElementTree as ET  # type: ignore

from secure_repo.core.models import Dependency

try:  # Python 3.11+
    import tomllib as _toml
except ModuleNotFoundError:  # pragma: no cover
    try:
        import tomli as _toml  # type: ignore
    except ModuleNotFoundError:  # pragma: no cover
        _toml = None

LOCKFILE_ECOSYSTEM = {
    "package-lock.json": "npm", "npm-shrinkwrap.json": "npm", "yarn.lock": "npm", "pnpm-lock.yaml": "npm",
    "bun.lockb": "npm", "poetry.lock": "PyPI", "pipfile.lock": "PyPI", "uv.lock": "PyPI", "pdm.lock": "PyPI",
    "cargo.lock": "crates.io", "gemfile.lock": "RubyGems", "composer.lock": "Packagist",
    "pubspec.lock": "Pub", "go.sum": "Go", "packages.lock.json": "NuGet", "gradle.lockfile": "Maven",
}


class ParseIssue:
    """Supply-chain issue discovered while parsing (insecure registry, etc.)."""

    def __init__(self, rule_id: str, manifest: str, line: int, detail: str, snippet: str = ""):
        self.rule_id, self.manifest, self.line, self.detail, self.snippet = rule_id, manifest, line, detail, snippet


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def normalize_name(ecosystem: str, name: str) -> str:
    if ecosystem == "PyPI":
        return re.sub(r"[-_.]+", "-", name).lower()
    if ecosystem in ("npm", "Packagist", "crates.io", "Pub", "RubyGems"):
        return name.lower()
    return name


def _find_line(lines: list[str], needle: str) -> int:
    if not needle:
        return 0
    pattern = re.compile(r"(?<![\w.\-/@])" + re.escape(needle) + r"(?![\w\-])", re.IGNORECASE)
    for number, line in enumerate(lines, 1):
        if pattern.search(line):
            return number
    return 0


def _load_toml(text: str) -> dict:
    if _toml is None:
        return {}
    try:
        return _toml.loads(text)
    except Exception:
        return {}


def _load_json(text: str):
    try:
        return json.loads(text)
    except ValueError:
        return None


def _safe_xml(text: str) -> ET.Element | None:
    cleaned = re.sub(r"<!DOCTYPE[^>\[]*(\[.*?\])?\s*>", "", text, flags=re.S | re.I)
    cleaned = re.sub(r"<!ENTITY[^>]*>", "", cleaned, flags=re.I)
    try:
        root = ET.fromstring(cleaned)  # defusedxml rejects entity expansion; DOCTYPE/ENTITY were also stripped above
    except ET.ParseError:
        return None
    for element in root.iter():
        if isinstance(element.tag, str) and "}" in element.tag:
            element.tag = element.tag.split("}", 1)[1]
    return root


_JSON_FILES = {"package.json", "package-lock.json", "npm-shrinkwrap.json", "composer.json", "composer.lock",
               "pipfile.lock", "packages.lock.json"}
_TOML_FILES = {"pyproject.toml", "pipfile", "poetry.lock", "uv.lock", "pdm.lock", "cargo.toml", "cargo.lock",
               "libs.versions.toml"}
_XML_FILES = {"pom.xml", "packages.config", "directory.packages.props"}


def syntax_error(rel_path: str, text: str) -> str | None:
    """Why a manifest cannot be parsed (broken JSON / TOML / XML), or None.

    The parsers deliberately tolerate bad input and return what they can, so a damaged manifest used to look like
    "no dependencies". Formats without a strict grammar (requirements.txt, go.mod, yarn.lock...) are not checked.
    """
    name = os.path.basename(rel_path).lower()
    if not text.strip():
        return None
    if name in _JSON_FILES:
        try:
            json.loads(text)
        except ValueError as exc:
            return f"invalid JSON: {str(exc)[:120]}"
    elif name in _TOML_FILES:
        if _toml is None:
            return None
        try:
            _toml.loads(text)
        except Exception as exc:  # tomllib.TOMLDecodeError (3.11+) / tomli.TOMLDecodeError
            return f"invalid TOML: {str(exc)[:120]}"
    elif name in _XML_FILES or name.endswith((".csproj", ".fsproj", ".vbproj")):
        if _safe_xml(text) is None:
            return "invalid XML"
    return None


_EXACT_VERSION = re.compile(r"^v?\d+(?:\.\d+)*(?:[-+.]?[0-9A-Za-z.\-+]*)?$")


def _is_exact(spec: str) -> bool:
    return bool(_EXACT_VERSION.match(spec.strip()))


# ---------------------------------------------------------------------------
# Python
# ---------------------------------------------------------------------------
_PEP508 = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._\-]*)\s*(\[[^\]]*\])?\s*(.*)$")


def _pep508(requirement: str, manifest: str, line: int, scope: str = "runtime") -> Dependency | None:
    requirement = requirement.split(";", 1)[0].strip()
    if not requirement:
        return None
    if " @ " in requirement or requirement.startswith(("git+", "hg+", "svn+", "bzr+", "http://", "https://", "file:")):
        name_part, _, url = requirement.partition(" @ ")
        if not url:
            url = name_part
            egg = re.search(r"[#&]egg=([A-Za-z0-9._\-]+)", url)
            name_part = egg.group(1) if egg else url.rsplit("/", 1)[-1].split("@")[0].replace(".git", "")
        source = "git" if re.match(r"^\s*(git|hg|svn|bzr)\+", url) else ("path" if url.startswith("file:") else "url")
        return Dependency(name=name_part.strip(), ecosystem="PyPI", version=None, spec=url.strip(),
                          manifest=manifest, line=line, scope=scope, source=source)
    match = _PEP508.match(requirement)
    if not match:
        return None
    name, _, spec = match.groups()
    spec = spec.strip().strip("()").strip()
    version = None
    exact = re.fullmatch(r"===?\s*([^\s,;*]+)", spec)
    if exact:
        version = exact.group(1)
    return Dependency(name=name, ecosystem="PyPI", version=version, spec=spec or "*", manifest=manifest, line=line,
                      scope=scope, locked=bool(version))


def parse_requirements(text: str, manifest: str, issues: list[ParseIssue]) -> list[Dependency]:
    deps = []
    scope = "dev" if re.search(r"dev|test|lint|doc", os.path.basename(manifest), re.I) else "runtime"
    for number, raw in enumerate(text.splitlines(), 1):
        line = re.split(r"\s+#", raw, maxsplit=1)[0].strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("-i", "--index-url", "--extra-index-url", "-f", "--find-links")):
            url = line.split(None, 1)[1] if " " in line else line.split("=", 1)[-1]
            if url.strip().startswith("http://"):
                issues.append(ParseIssue("SR-DEP-006", manifest, number, f"Package index over HTTP: {url.strip()}", raw.strip()))
            continue
        if line.startswith("--trusted-host"):
            issues.append(ParseIssue("SR-DEP-006", manifest, number, "pip --trusted-host disables TLS verification", raw.strip()))
            continue
        if line.startswith(("-r", "--requirement", "-c", "--constraint")):
            continue
        if line.startswith(("-e", "--editable")):
            line = line.split(None, 1)[1] if " " in line else ""
            if line.startswith((".", "/")):
                continue
        if line.startswith("-"):
            continue
        dep = _pep508(line.split(" --hash")[0].rstrip("\\").strip(), manifest, number, scope)
        if dep:
            deps.append(dep)
    return deps


def parse_pyproject(text: str, manifest: str, issues: list[ParseIssue]) -> list[Dependency]:
    data = _load_toml(text)
    lines = text.splitlines()
    deps: list[Dependency] = []

    def add_pep(req: str, scope: str) -> None:
        name = _PEP508.match(req)
        dep = _pep508(req, manifest, _find_line(lines, name.group(1)) if name else 0, scope)
        if dep:
            deps.append(dep)

    project = data.get("project", {})
    for req in project.get("dependencies", []) or []:
        add_pep(req, "runtime")
    for group in (project.get("optional-dependencies", {}) or {}).values():
        for req in group:
            add_pep(req, "optional")
    for group in (data.get("dependency-groups", {}) or {}).values():
        for req in group:
            if isinstance(req, str):
                add_pep(req, "dev")

    poetry = data.get("tool", {}).get("poetry", {})
    sections = [(poetry.get("dependencies", {}), "runtime"), (poetry.get("dev-dependencies", {}), "dev")]
    for group in (poetry.get("group", {}) or {}).values():
        sections.append((group.get("dependencies", {}), "dev"))
    for table, scope in sections:
        for name, spec in (table or {}).items():
            if name.lower() == "python":
                continue
            deps.append(_poetry_dep(name, spec, manifest, _find_line(lines, name), scope))
    return deps


def _poetry_dep(name: str, spec, manifest: str, line: int, scope: str) -> Dependency:
    source, version, text = "registry", None, ""
    if isinstance(spec, dict):
        if "git" in spec:
            source, text = "git", spec["git"]
        elif "path" in spec:
            source, text = "path", spec["path"]
        elif "url" in spec:
            source, text = "url", spec["url"]
        else:
            text = str(spec.get("version", "*"))
    else:
        text = str(spec)
    if source == "registry" and re.fullmatch(r"=?=?\s*\d[\w.]*", text.strip()):
        version = text.strip().lstrip("=")
    return Dependency(name=name, ecosystem="PyPI", version=version, spec=text, manifest=manifest, line=line,
                      scope=scope, source=source, locked=bool(version))


def parse_pipfile(text: str, manifest: str, issues: list[ParseIssue]) -> list[Dependency]:
    data = _load_toml(text)
    lines = text.splitlines()
    deps = []
    for source in data.get("source", []) or []:
        url = str(source.get("url", ""))
        if url.startswith("http://") or source.get("verify_ssl") is False:
            issues.append(ParseIssue("SR-DEP-006", manifest, _find_line(lines, "url"), f"Insecure package source: {url}"))
    for section, scope in (("packages", "runtime"), ("dev-packages", "dev")):
        for name, spec in (data.get(section, {}) or {}).items():
            dep = _poetry_dep(name, spec, manifest, _find_line(lines, name), scope)
            dep.version = None
            if isinstance(spec, str) and spec.startswith("=="):
                dep.version = spec[2:]
            deps.append(dep)
    return deps


def parse_pipfile_lock(text: str, manifest: str, issues: list[ParseIssue]) -> list[Dependency]:
    data = _load_json(text) or {}
    deps = []
    for section, scope in (("default", "runtime"), ("develop", "dev")):
        for name, info in (data.get(section) or {}).items():
            version = str(info.get("version", "")).lstrip("=") or None
            deps.append(Dependency(name=name, ecosystem="PyPI", version=version, spec=version or "", manifest=manifest,
                                   direct=False, scope=scope, locked=True))
    return deps


def parse_toml_lock(ecosystem: str) -> Callable:
    def parser(text: str, manifest: str, issues: list[ParseIssue]) -> list[Dependency]:
        data = _load_toml(text)
        deps = []
        for package in data.get("package", []) or []:
            name, version = package.get("name"), package.get("version")
            source = package.get("source")
            if not name or not version:
                continue
            if ecosystem == "crates.io" and not source:
                continue  # workspace member
            if isinstance(source, dict) and ({"editable", "virtual", "path", "directory"} & set(source)):
                continue
            src_kind = "git" if (isinstance(source, str) and source.startswith("git+")) or (
                isinstance(source, dict) and "git" in source) else "registry"
            deps.append(Dependency(name=name, ecosystem=ecosystem, version=str(version), spec=str(version),
                                   manifest=manifest, direct=False, locked=True, source=src_kind))
        return deps

    return parser


def parse_setup_py(text: str, manifest: str, issues: list[ParseIssue]) -> list[Dependency]:
    deps = []
    lines = text.splitlines()
    for block in re.findall(r"install_requires\s*=\s*\[(.*?)\]", text, flags=re.S):
        for req in re.findall(r"['\"]([^'\"]+)['\"]", block):
            name = _PEP508.match(req)
            dep = _pep508(req, manifest, _find_line(lines, name.group(1)) if name else 0)
            if dep:
                deps.append(dep)
    return deps


def parse_setup_cfg(text: str, manifest: str, issues: list[ParseIssue]) -> list[Dependency]:
    parser = configparser.ConfigParser(interpolation=None)
    try:
        parser.read_string(text)
    except configparser.Error:
        return []
    raw = parser.get("options", "install_requires", fallback="")
    lines = text.splitlines()
    deps = []
    for req in raw.splitlines():
        req = req.strip()
        if req:
            name = _PEP508.match(req)
            dep = _pep508(req, manifest, _find_line(lines, name.group(1)) if name else 0)
            if dep:
                deps.append(dep)
    return deps


# ---------------------------------------------------------------------------
# JavaScript
# ---------------------------------------------------------------------------

def _npm_source(spec: str) -> str:
    spec = spec.strip()
    if re.match(r"^(git(\+\w+)?:|git@|github:|gitlab:|bitbucket:)", spec) or re.match(r"^[\w.-]+/[\w.-]+(#.*)?$", spec):
        return "git"
    if spec.startswith(("http://", "https://")):
        return "url"
    if spec.startswith(("file:", "link:", "workspace:", "portal:", ".", "/")):
        return "path"
    return "registry"


def parse_package_json(text: str, manifest: str, issues: list[ParseIssue]) -> list[Dependency]:
    data = _load_json(text)
    if not isinstance(data, dict):
        return []
    lines = text.splitlines()
    deps = []
    for section, scope in (("dependencies", "runtime"), ("devDependencies", "dev"),
                           ("optionalDependencies", "optional"), ("peerDependencies", "peer")):
        for name, spec in (data.get(section) or {}).items():
            spec = str(spec)
            source = _npm_source(spec)
            version = spec.lstrip("=v") if source == "registry" and _is_exact(spec.lstrip("=")) else None
            if spec.startswith("npm:"):
                alias = spec[4:]
                name, _, alias_spec = alias.rpartition("@") if alias.count("@") > (1 if alias.startswith("@") else 0) else (alias, "", "")
                version = alias_spec if _is_exact(alias_spec) else None
            line = _find_line(lines, f'"{name}"')
            if source == "url" and spec.startswith("http://"):
                issues.append(ParseIssue("SR-DEP-006", manifest, line, f"{name} is downloaded over HTTP: {spec}", f'"{name}": "{spec}"'))
            deps.append(Dependency(name=name, ecosystem="npm", version=version, spec=spec, manifest=manifest,
                                   line=line, scope=scope, source=source, locked=bool(version)))
    return deps


def parse_package_lock(text: str, manifest: str, issues: list[ParseIssue]) -> list[Dependency]:
    data = _load_json(text)
    if not isinstance(data, dict):
        return []
    deps = []
    insecure_reported = False
    packages = data.get("packages")
    if isinstance(packages, dict):
        for key, info in packages.items():
            if not key or "node_modules/" not in key or info.get("link"):
                continue
            name = info.get("name") or key.rsplit("node_modules/", 1)[-1]
            version = info.get("version")
            if not version:
                continue
            resolved = str(info.get("resolved", ""))
            if resolved.startswith("http://") and not insecure_reported:
                issues.append(ParseIssue("SR-DEP-006", manifest, 0, f"Packages resolved over HTTP (e.g. {resolved})"))
                insecure_reported = True
            deps.append(Dependency(name=name, ecosystem="npm", version=version, spec=version, manifest=manifest,
                                   direct=False, scope="dev" if info.get("dev") else "runtime", locked=True))
        return deps

    def walk(tree: dict) -> None:
        for name, info in (tree or {}).items():
            if isinstance(info, dict) and info.get("version"):
                deps.append(Dependency(name=name, ecosystem="npm", version=info["version"], spec=info["version"],
                                       manifest=manifest, direct=False, scope="dev" if info.get("dev") else "runtime",
                                       locked=True))
                walk(info.get("dependencies"))

    walk(data.get("dependencies"))
    return deps


def parse_yarn_lock(text: str, manifest: str, issues: list[ParseIssue]) -> list[Dependency]:
    deps = []
    current: str | None = None
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith(" ") and line.rstrip().endswith(":"):
            header = line.rstrip()[:-1].split(",")[0].strip().strip('"')
            if header == "__metadata" or "@workspace:" in header or "@patch:" in header:
                current = None
                continue
            name = header.rsplit("@", 1)[0] if header.count("@") > (1 if header.startswith("@") else 0) else header
            current = name
            continue
        match = re.match(r'^\s+version:?\s+"?([^"\s]+)"?', line)
        if match and current:
            deps.append(Dependency(name=current, ecosystem="npm", version=match.group(1), spec=match.group(1),
                                   manifest=manifest, direct=False, locked=True))
            current = None
    return deps


def parse_pnpm_lock(text: str, manifest: str, issues: list[ParseIssue]) -> list[Dependency]:
    deps = []
    seen = set()
    in_packages = False
    entry = re.compile(r"^  ['\"]?/?((?:@[^/@\s'\"]+/)?[^/@\s'\"(]+)[@/](\d[^:'\"()\s_]*)")
    for line in text.splitlines():
        if re.match(r"^(packages|snapshots):\s*$", line):
            in_packages = True
            continue
        if line and not line.startswith(" "):
            in_packages = False
            continue
        if in_packages:
            match = entry.match(line)
            if match and match.groups() not in seen:
                seen.add(match.groups())
                name, version = match.groups()
                deps.append(Dependency(name=name, ecosystem="npm", version=version, spec=version, manifest=manifest,
                                       direct=False, locked=True))
    return deps


# ---------------------------------------------------------------------------
# Go / Rust / Ruby / PHP / Dart
# ---------------------------------------------------------------------------

def parse_go_mod(text: str, manifest: str, issues: list[ParseIssue]) -> list[Dependency]:
    deps = []
    in_block = False
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        entry = None
        if in_block:
            entry = line
        elif line.startswith("require ") and "(" not in line:
            entry = line[len("require "):]
        if not entry or entry.startswith("//"):
            continue
        parts = entry.split()
        if len(parts) >= 2:
            indirect = "// indirect" in entry
            version = parts[1].lstrip("v").replace("+incompatible", "")
            deps.append(Dependency(name=parts[0], ecosystem="Go", version=version, spec=parts[1], manifest=manifest,
                                   line=number, direct=not indirect, locked=True))
    return deps


def parse_cargo_toml(text: str, manifest: str, issues: list[ParseIssue]) -> list[Dependency]:
    data = _load_toml(text)
    lines = text.splitlines()
    tables = []
    for key, scope in (("dependencies", "runtime"), ("dev-dependencies", "dev"), ("build-dependencies", "build")):
        tables.append((data.get(key, {}), scope))
        for target in (data.get("target", {}) or {}).values():
            tables.append((target.get(key, {}), scope))
    tables.append(((data.get("workspace", {}) or {}).get("dependencies", {}), "runtime"))
    deps = []
    for table, scope in tables:
        for name, spec in (table or {}).items():
            source, text_spec = "registry", ""
            if isinstance(spec, dict):
                if "git" in spec:
                    source, text_spec = "git", spec["git"]
                elif "path" in spec:
                    source, text_spec = "path", spec["path"]
                elif spec.get("workspace"):
                    continue
                else:
                    text_spec = str(spec.get("version", "*"))
                name = spec.get("package", name)
            else:
                text_spec = str(spec)
            version = text_spec[1:] if source == "registry" and text_spec.startswith("=") and _is_exact(text_spec[1:]) else None
            deps.append(Dependency(name=name, ecosystem="crates.io", version=version, spec=text_spec, manifest=manifest,
                                   line=_find_line(lines, name), scope=scope, source=source, locked=bool(version)))
    return deps


def parse_gemfile(text: str, manifest: str, issues: list[ParseIssue]) -> list[Dependency]:
    deps = []
    gem = re.compile(r"""^\s*gem\s+['"]([^'"]+)['"]\s*((?:,\s*['"][^'"]+['"]\s*)*)(.*)$""")
    for number, line in enumerate(text.splitlines(), 1):
        if re.match(r"^\s*source\s+['\"]http://", line):
            issues.append(ParseIssue("SR-DEP-006", manifest, number, "RubyGems source over HTTP", line.strip()))
        match = gem.match(line)
        if not match:
            continue
        name, versions, rest = match.groups()
        specs = re.findall(r"['\"]([^'\"]+)['\"]", versions or "")
        spec = ", ".join(specs) or "*"
        source = "git" if re.search(r"\b(git|github|gitlab|bitbucket)\s*:", rest) else (
            "path" if re.search(r"\bpath\s*:", rest) else "registry")
        version = None
        if len(specs) == 1 and (_is_exact(specs[0]) or specs[0].startswith("= ")):
            version = specs[0].lstrip("= ").strip()
        deps.append(Dependency(name=name, ecosystem="RubyGems", version=version, spec=spec, manifest=manifest,
                               line=number, source=source, locked=bool(version)))
    return deps


def parse_gemfile_lock(text: str, manifest: str, issues: list[ParseIssue]) -> list[Dependency]:
    deps = []
    section = ""
    for number, line in enumerate(text.splitlines(), 1):
        if line and not line.startswith(" "):
            section = line.strip()
            continue
        if line.strip().startswith("remote: http://"):
            issues.append(ParseIssue("SR-DEP-006", manifest, number, "Gems resolved from an HTTP remote", line.strip()))
        match = re.match(r"^    ([A-Za-z0-9_.\-]+) \(([^)]+)\)$", line)
        if match and section in ("GEM", "GIT", "PATH"):
            version = re.sub(r"-(?:x86|x64|arm|aarch|java|universal|mingw|mswin|darwin|linux|musl).*$", "", match.group(2))
            deps.append(Dependency(name=match.group(1), ecosystem="RubyGems", version=version, spec=match.group(2),
                                   manifest=manifest, direct=False, locked=True,
                                   source="registry" if section == "GEM" else section.lower()))
    return deps


def parse_composer_json(text: str, manifest: str, issues: list[ParseIssue]) -> list[Dependency]:
    data = _load_json(text)
    if not isinstance(data, dict):
        return []
    lines = text.splitlines()
    if (data.get("config") or {}).get("secure-http") is False:
        issues.append(ParseIssue("SR-DEP-006", manifest, _find_line(lines, "secure-http"), "Composer secure-http is disabled"))
    for repo in data.get("repositories") or []:
        if isinstance(repo, dict) and str(repo.get("url", "")).startswith("http://"):
            issues.append(ParseIssue("SR-DEP-006", manifest, _find_line(lines, repo["url"]), f"Repository over HTTP: {repo['url']}"))
    deps = []
    for section, scope in (("require", "runtime"), ("require-dev", "dev")):
        for name, spec in (data.get(section) or {}).items():
            if name == "php" or name.startswith(("ext-", "lib-")) or "/" not in name:
                continue
            spec = str(spec)
            version = spec.lstrip("v") if _is_exact(spec) else None
            deps.append(Dependency(name=name, ecosystem="Packagist", version=version, spec=spec, manifest=manifest,
                                   line=_find_line(lines, f'"{name}"'), scope=scope, locked=bool(version)))
    return deps


def parse_composer_lock(text: str, manifest: str, issues: list[ParseIssue]) -> list[Dependency]:
    data = _load_json(text) or {}
    deps = []
    for section, scope in (("packages", "runtime"), ("packages-dev", "dev")):
        for package in data.get(section) or []:
            name, version = package.get("name"), str(package.get("version", "")).lstrip("v")
            if name and version:
                deps.append(Dependency(name=name, ecosystem="Packagist", version=version, spec=version,
                                       manifest=manifest, direct=False, scope=scope, locked=True))
    return deps


def parse_pubspec(text: str, manifest: str, issues: list[ParseIssue]) -> list[Dependency]:
    deps = []
    section = None
    lines = text.splitlines()
    for number, line in enumerate(lines, 1):
        top = re.match(r"^([A-Za-z_]+):\s*$", line)
        if top:
            section = top.group(1) if top.group(1) in ("dependencies", "dev_dependencies") else None
            continue
        if line and not line.startswith(" "):
            section = None
            continue
        if not section:
            continue
        match = re.match(r"^  ([A-Za-z0-9_]+):\s*(.*)$", line)
        if not match:
            continue
        name, spec = match.group(1), match.group(2).strip().strip("'\"")
        source = "registry"
        if not spec:
            nested = " ".join(lines[number:number + 3])
            if "sdk:" in nested:
                continue
            source = "git" if "git:" in nested else ("path" if "path:" in nested else "registry")
        version = spec if _is_exact(spec) else None
        deps.append(Dependency(name=name, ecosystem="Pub", version=version, spec=spec or source, manifest=manifest,
                               line=number, scope="dev" if section == "dev_dependencies" else "runtime",
                               source=source, locked=bool(version)))
    return deps


def parse_pubspec_lock(text: str, manifest: str, issues: list[ParseIssue]) -> list[Dependency]:
    deps = []
    name = None
    for line in text.splitlines():
        header = re.match(r"^  ([A-Za-z0-9_]+):\s*$", line)
        if header:
            name = header.group(1)
            continue
        version = re.match(r'^    version:\s*"?([^"\s]+)"?', line)
        if version and name:
            deps.append(Dependency(name=name, ecosystem="Pub", version=version.group(1), spec=version.group(1),
                                   manifest=manifest, direct=False, locked=True))
            name = None
    return deps


# ---------------------------------------------------------------------------
# JVM / .NET
# ---------------------------------------------------------------------------

def parse_pom(text: str, manifest: str, issues: list[ParseIssue]) -> list[Dependency]:
    root = _safe_xml(text)
    if root is None:
        return []
    lines = text.splitlines()
    props: dict[str, str] = {}
    properties = root.find("properties")
    if properties is not None:
        for prop in properties:
            if isinstance(prop.tag, str):
                props[prop.tag] = (prop.text or "").strip()
    project_version = (root.findtext("version") or root.findtext("parent/version") or "").strip()
    props.setdefault("project.version", project_version)

    def resolve(value: str) -> str:
        return re.sub(r"\$\{([^}]+)\}", lambda m: props.get(m.group(1), m.group(0)), value or "")

    for repo in root.iter("repository"):
        url = (repo.findtext("url") or "").strip()
        if url.startswith("http://"):
            issues.append(ParseIssue("SR-DEP-006", manifest, _find_line(lines, url), f"Maven repository over HTTP: {url}"))
    deps = []
    for dep in root.iter("dependency"):
        group, artifact = (dep.findtext("groupId") or "").strip(), (dep.findtext("artifactId") or "").strip()
        if not group or not artifact:
            continue
        spec = resolve((dep.findtext("version") or "").strip())
        version = spec if spec and _is_exact(spec) and "${" not in spec else None
        scope = (dep.findtext("scope") or "compile").strip()
        deps.append(Dependency(name=f"{resolve(group)}:{artifact}", ecosystem="Maven", version=version, spec=spec or "managed",
                               manifest=manifest, line=_find_line(lines, artifact),
                               scope="dev" if scope == "test" else "runtime", locked=bool(version)))
    return deps


def parse_gradle(text: str, manifest: str, issues: list[ParseIssue]) -> list[Dependency]:
    deps = []
    pattern = re.compile(
        r"\b(implementation|api|compileOnly|runtimeOnly|testImplementation|testRuntimeOnly|androidTestImplementation|"
        r"kapt|ksp|annotationProcessor|classpath|compile|testCompile)\s*\(?\s*['\"]([\w.\-]+):([\w.\-]+):([^'\"@:]+)['\"]")
    for number, line in enumerate(text.splitlines(), 1):
        if re.search(r"url\s*[=(]?\s*['\"]http://", line):
            issues.append(ParseIssue("SR-DEP-006", manifest, number, "Gradle repository over HTTP", line.strip()))
        for match in pattern.finditer(line):
            config, group, artifact, spec = match.groups()
            version = spec if _is_exact(spec) and "$" not in spec else None
            deps.append(Dependency(name=f"{group}:{artifact}", ecosystem="Maven", version=version, spec=spec,
                                   manifest=manifest, line=number, scope="dev" if "test" in config.lower() else "runtime",
                                   locked=bool(version)))
    return deps


def parse_version_catalog(text: str, manifest: str, issues: list[ParseIssue]) -> list[Dependency]:
    data = _load_toml(text)
    versions = data.get("versions", {}) or {}
    lines = text.splitlines()
    deps = []
    for alias, spec in (data.get("libraries", {}) or {}).items():
        module, version = None, None
        if isinstance(spec, str) and spec.count(":") == 2:
            group, artifact, version = spec.split(":")
            module = f"{group}:{artifact}"
        elif isinstance(spec, dict):
            module = spec.get("module") or (f"{spec['group']}:{spec['name']}" if "group" in spec and "name" in spec else None)
            ver = spec.get("version")
            if isinstance(ver, dict):
                ver = versions.get(ver.get("ref", "")) if "ref" in ver else ver.get("strictly") or ver.get("require")
            version = ver if isinstance(ver, str) else None
        if module:
            exact = version if version and _is_exact(version) else None
            deps.append(Dependency(name=module, ecosystem="Maven", version=exact, spec=version or "*", manifest=manifest,
                                   line=_find_line(lines, alias), locked=bool(exact)))
    return deps


def parse_dotnet_project(text: str, manifest: str, issues: list[ParseIssue]) -> list[Dependency]:
    root = _safe_xml(text)
    if root is None:
        return []
    lines = text.splitlines()
    deps = []
    for tag in ("PackageReference", "PackageVersion", "package"):
        for element in root.iter(tag):
            name = element.get("Include") or element.get("Update") or element.get("id")
            spec = element.get("Version") or element.findtext("Version") or element.get("version") or ""
            if not name:
                continue
            spec = spec.strip()
            exact = spec.strip("[]") if re.fullmatch(r"\[?\d[\w.\-]*\]?", spec) else None
            deps.append(Dependency(name=name, ecosystem="NuGet", version=exact, spec=spec or "*", manifest=manifest,
                                   line=_find_line(lines, name), locked=bool(exact)))
    return deps


def parse_nuget_lock(text: str, manifest: str, issues: list[ParseIssue]) -> list[Dependency]:
    data = _load_json(text) or {}
    deps = []
    for framework in (data.get("dependencies") or {}).values():
        for name, info in (framework or {}).items():
            version = info.get("resolved")
            if version and info.get("type") != "Project":
                deps.append(Dependency(name=name, ecosystem="NuGet", version=version, spec=version, manifest=manifest,
                                       direct=info.get("type") == "Direct", locked=True))
    return deps


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------
Parser = Callable[[str, str, list[ParseIssue]], list[Dependency]]


def parser_for(rel_path: str) -> tuple[Parser, bool] | None:
    """Return (parser, is_lockfile) for a manifest path."""
    name = os.path.basename(rel_path)
    lower = name.lower()
    if re.fullmatch(r"(.*[-_.])?requirements([-_.][\w.-]*)?\.(txt|in|lock)", lower) or (
            "/requirements/" in "/" + rel_path.lower() and lower.endswith(".txt")):
        return parse_requirements, False
    table: dict[str, tuple[Parser, bool]] = {
        "pyproject.toml": (parse_pyproject, False), "pipfile": (parse_pipfile, False),
        "pipfile.lock": (parse_pipfile_lock, True), "poetry.lock": (parse_toml_lock("PyPI"), True),
        "uv.lock": (parse_toml_lock("PyPI"), True), "pdm.lock": (parse_toml_lock("PyPI"), True),
        "setup.py": (parse_setup_py, False), "setup.cfg": (parse_setup_cfg, False),
        "package.json": (parse_package_json, False), "package-lock.json": (parse_package_lock, True),
        "npm-shrinkwrap.json": (parse_package_lock, True), "yarn.lock": (parse_yarn_lock, True),
        "pnpm-lock.yaml": (parse_pnpm_lock, True), "go.mod": (parse_go_mod, False),
        "cargo.toml": (parse_cargo_toml, False), "cargo.lock": (parse_toml_lock("crates.io"), True),
        "gemfile": (parse_gemfile, False), "gems.rb": (parse_gemfile, False),
        "gemfile.lock": (parse_gemfile_lock, True), "composer.json": (parse_composer_json, False),
        "composer.lock": (parse_composer_lock, True), "pubspec.yaml": (parse_pubspec, False),
        "pubspec.lock": (parse_pubspec_lock, True), "pom.xml": (parse_pom, False),
        "build.gradle": (parse_gradle, False), "build.gradle.kts": (parse_gradle, False),
        "libs.versions.toml": (parse_version_catalog, False), "packages.config": (parse_dotnet_project, False),
        "directory.packages.props": (parse_dotnet_project, False), "packages.lock.json": (parse_nuget_lock, True),
    }
    if lower in table:
        return table[lower]
    if lower.endswith((".csproj", ".fsproj", ".vbproj")):
        return parse_dotnet_project, False
    return None


def is_manifest(rel_path: str) -> bool:
    return parser_for(rel_path) is not None


def is_lockfile(rel_path: str) -> bool:
    return os.path.basename(rel_path).lower() in LOCKFILE_ECOSYSTEM
