"""Repository enumeration and structure (tree) building."""

from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass
from collections.abc import Iterable

from secure_repo.core.languages import detect_language
from secure_repo.core.models import SEVERITIES, SEVERITY_RANK

REPORTS_DIR_NAME = "secure-repo-reports"

# Folders that are never source code of the project, whatever their location.
ALWAYS_EXCLUDED_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "bower_components", "jspm_packages", "__pycache__",
    ".venv", "venv", ".tox", ".nox", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".idea",
    ".next", ".nuxt", ".svelte-kit", ".gradle", ".terraform", "DerivedData", ".dart_tool", "site-packages",
    ".parcel-cache", ".turbo", ".angular", REPORTS_DIR_NAME,
}
# Folders whose names are common in real source trees (a "build" or "target" package, a "vendor" module...).
# They are skipped only when there is evidence that they hold generated or third-party content.
CONTEXTUAL_DIRS = {"build", "dist", "target", "vendor", "obj", "coverage", ".cache", "Pods"}
EXCLUDED_DIRS = ALWAYS_EXCLUDED_DIRS | CONTEXTUAL_DIRS
ARTIFACT_EXT = {".class", ".o", ".obj", ".a", ".so", ".dylib", ".dll", ".pyc", ".pyo", ".whl", ".jar", ".war", ".ear",
                ".egg", ".exe", ".map", ".tsbuildinfo", ".gcda", ".gcno", ".pdb"}
VENDOR_SIBLINGS = ("go.mod", "composer.json", "Gemfile")
COUNT_CAP = 5000
SKIP_CONTENT_NAMES = {
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "cargo.lock",
    "composer.lock", "gemfile.lock", "go.sum", "pipfile.lock", "uv.lock", "pubspec.lock", "packages.lock.json",
    "bun.lockb", "mix.lock", "pdm.lock",
}
SKIP_CONTENT_EXT = {".map", ".svg", ".lock", ".min.js", ".min.css", ".snap", ".ipynb"}
TEST_PATH_RE = re.compile(
    r"(^|/)(tests?|__tests__|spec|specs|testing|fixtures?|__mocks__|e2e|testdata)(/|$)|(^|/)test_[^/]*$|"
    r"_test\.[a-z]+$|\.(test|spec)\.[a-z]+$", re.IGNORECASE)


@dataclass
class FileInfo:
    rel: str
    abs: str
    size: int
    language: str
    is_symlink: bool = False

    @property
    def in_test(self) -> bool:
        return bool(TEST_PATH_RE.search(self.rel))

    @property
    def scannable(self) -> bool:
        name = os.path.basename(self.rel).lower()
        if name in SKIP_CONTENT_NAMES:
            return False
        return not any(name.endswith(ext) for ext in SKIP_CONTENT_EXT)


def _gitignored_names(directory: str, cache: dict[str, set]) -> set:
    """Plain directory names (``build/``, ``/dist``, ``**/target``) listed in the .gitignore of ``directory``."""
    if directory in cache:
        return cache[directory]
    names = set()
    try:
        with open(os.path.join(directory, ".gitignore"), encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.strip()
                if not line or line.startswith(("#", "!")):
                    continue
                line = line.lstrip("/")
                if line.startswith("**/"):
                    line = line[3:]
                line = line.rstrip("/")
                if line and not any(ch in line for ch in "*?[/"):
                    names.add(line)
    except OSError:
        pass
    cache[directory] = names
    return names


def _has_artifacts(directory: str) -> bool:
    """True when the folder (or one of its first sub-folders) holds compiled/build output."""
    try:
        with os.scandir(directory) as entries:
            subdirs = []
            for index, entry in enumerate(entries):
                if index > 300:
                    break
                if entry.is_dir(follow_symlinks=False):
                    subdirs.append(entry.path)
                elif os.path.splitext(entry.name)[1].lower() in ARTIFACT_EXT:
                    return True
        for sub in subdirs[:12]:
            with os.scandir(sub) as entries:
                for index, entry in enumerate(entries):
                    if index > 60:
                        break
                    if entry.is_file(follow_symlinks=False) and os.path.splitext(entry.name)[1].lower() in ARTIFACT_EXT:
                        return True
    except OSError:
        return False
    return False


def contextual_exclusion(name: str, full: str, rel: str, root: str, cache: dict[str, set]) -> str | None:
    """Why a CONTEXTUAL_DIRS folder is skipped (None = it looks like real source, analyze it)."""
    parent = os.path.dirname(full)
    if name in _gitignored_names(root, cache) or name in _gitignored_names(parent, cache):
        return "listed in .gitignore"
    if name == "vendor":
        if "/" not in rel:
            return "vendor/ at the repository root"
        if any(os.path.isfile(os.path.join(parent, sibling)) for sibling in VENDOR_SIBLINGS):
            return "vendored dependencies (next to go.mod / composer.json / Gemfile)"
    if name == "Pods" and os.path.isfile(os.path.join(parent, "Podfile")):
        return "CocoaPods dependencies (next to Podfile)"
    if _has_artifacts(full):
        return "contains build artifacts"
    return None


def _count_files(directory: str) -> int:
    total = 0
    for _current, _dirs, names in os.walk(directory, followlinks=False):
        total += len(names)
        if total >= COUNT_CAP:
            return COUNT_CAP
    return total


def enumerate_files(root: str, exclude_globs: Iterable[str] | None = None,
                    skipped: list[dict] | None = None) -> list[FileInfo]:
    """List the files to analyze. ``skipped`` (optional) receives every folder that was NOT entered, with the reason."""
    exclude_globs = list(exclude_globs or [])
    files: list[FileInfo] = []
    root = os.path.abspath(root)
    gitignore_cache: dict[str, set] = {}

    def note(rel: str, reason: str, kind: str, full: str | None = None) -> None:
        if skipped is None:
            return
        entry = {"path": rel, "reason": reason, "kind": kind, "files": None}
        if kind == "contextual" and full:
            entry["files"] = _count_files(full)
        skipped.append(entry)

    for current, dirs, names in os.walk(root, topdown=True, followlinks=False):
        rel_dir = os.path.relpath(current, root).replace(os.sep, "/")
        rel_dir = "" if rel_dir == "." else rel_dir
        kept = []
        for directory in dirs:
            full = os.path.join(current, directory)
            rel = f"{rel_dir}/{directory}" if rel_dir else directory
            if os.path.islink(full):
                note(rel, "symbolic link (never followed)", "always")
                continue
            if directory in ALWAYS_EXCLUDED_DIRS:
                note(rel, "dependency, cache or tooling folder", "always")
                continue
            if os.path.isfile(os.path.join(full, "pyvenv.cfg")):
                note(rel, "Python virtual environment", "always")
                continue
            if directory in CONTEXTUAL_DIRS:
                reason = contextual_exclusion(directory, full, rel, root, gitignore_cache)
                if reason:
                    note(rel, reason, "contextual", full)
                    continue
            if any(fnmatch.fnmatch(rel, g) or fnmatch.fnmatch(directory, g) for g in exclude_globs):
                continue
            kept.append(directory)
        dirs[:] = sorted(kept, key=str.lower)
        for name in sorted(names, key=str.lower):
            full = os.path.join(current, name)
            rel = f"{rel_dir}/{name}" if rel_dir else name
            if any(fnmatch.fnmatch(rel, g) or fnmatch.fnmatch(name, g) for g in exclude_globs):
                continue
            is_link = os.path.islink(full)
            try:
                size = os.lstat(full).st_size
            except OSError:
                continue
            files.append(FileInfo(rel=rel, abs=full, size=size, language=detect_language(rel), is_symlink=is_link))
    return files


def read_text(info: FileInfo, max_bytes: int) -> str | None:
    """Return decoded text, or None for binary / oversized / unreadable files."""
    if info.is_symlink or info.size > max_bytes:
        return None
    try:
        with open(info.abs, "rb") as handle:
            data = handle.read(max_bytes + 1)
    except OSError:
        return None
    if b"\x00" in data[:8192]:
        return None
    text = data.decode("utf-8", errors="replace")
    if text.startswith("﻿"):
        text = text[1:]
    return text


class StructureTree:
    """Hierarchical view of the repository used for the box map and tree views."""

    def __init__(self, name: str, files: list[FileInfo], max_file_nodes: int = 25000):
        self.root: dict = self._dir(name, "")
        self.index: dict[str, dict] = {"": self.root}
        collapse = len(files) > max_file_nodes
        for info in files:
            parts = info.rel.split("/")
            node = self.root
            for depth, part in enumerate(parts[:-1]):
                path = "/".join(parts[: depth + 1])
                child = self.index.get(path)
                if child is None:
                    child = self._dir(part, path)
                    node["children"].append(child)
                    self.index[path] = child
                node = child
            for ancestor in self._ancestors(info.rel):
                ancestor["size"] += info.size
                ancestor["files"] += 1
            if collapse and len(parts) > 3:
                continue
            leaf = {"name": parts[-1], "path": info.rel, "type": "file", "size": info.size, "lines": 0,
                    "language": info.language, "findings": 0, "risk": None, "severity": {}}
            node["children"].append(leaf)
            self.index[info.rel] = leaf

    @staticmethod
    def _dir(name: str, path: str) -> dict:
        return {"name": name, "path": path, "type": "dir", "size": 0, "lines": 0, "files": 0, "findings": 0,
                "risk": None, "severity": {}, "children": []}

    def _ancestors(self, rel: str) -> list[dict]:
        parts = rel.split("/")[:-1]
        nodes = [self.root]
        for depth in range(len(parts)):
            node = self.index.get("/".join(parts[: depth + 1]))
            if node is not None:
                nodes.append(node)
        return nodes

    def set_lines(self, rel: str, lines: int) -> None:
        leaf = self.index.get(rel)
        if leaf is not None and leaf["type"] == "file":
            leaf["lines"] = lines
        for ancestor in self._ancestors(rel):
            ancestor["lines"] += lines

    def add_finding(self, rel: str, severity: str) -> None:
        targets = self._ancestors(rel) if rel not in ("", ".") else [self.root]
        leaf = self.index.get(rel)
        if leaf is not None and leaf is not self.root:
            targets = targets + [leaf]
        for node in targets:
            node["findings"] += 1
            node["severity"][severity] = node["severity"].get(severity, 0) + 1
            if node["risk"] is None or SEVERITY_RANK[severity] < SEVERITY_RANK[node["risk"]]:
                node["risk"] = severity

    def to_dict(self) -> dict:
        def _sort(node: dict) -> dict:
            if node["type"] == "dir":
                node["children"].sort(key=lambda c: (c["type"] != "dir", -c["size"], c["name"].lower()))
                for child in node["children"]:
                    _sort(child)
            return node

        return _sort(self.root)

    def render_text(self, max_depth: int = 6) -> str:
        return render_structure_text(self.to_dict(), max_depth)


def render_structure_text(root: dict, max_depth: int = 6) -> str:
    """Plain-text tree of a structure dictionary annotated with finding counts."""
    lines = [f"{root['name']}/  ({root['files']} files)"]

    def _walk(node: dict, prefix: str, depth: int) -> None:
        children = node.get("children", [])
        for index, child in enumerate(children):
            last = index == len(children) - 1
            branch = "└── " if last else "├── "
            marker = ""
            if child["findings"]:
                counts = ", ".join(f"{child['severity'][s]} {s}" for s in SEVERITIES if child["severity"].get(s))
                marker = f"  [!] {counts}"
            suffix = "/" if child["type"] == "dir" else ""
            lines.append(f"{prefix}{branch}{child['name']}{suffix}{marker}")
            if child["type"] == "dir" and depth < max_depth:
                _walk(child, prefix + ("    " if last else "│   "), depth + 1)

    _walk(root, "", 1)
    return "\n".join(lines)
