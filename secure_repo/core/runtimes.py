"""Language runtimes that no longer receive security fixes (end-of-life), found in version files, Dockerfiles and CI.

The table holds the dates published by the projects; it is reviewed with every release (see docs/releasing.md).
Only well-known, long-established release lines are listed so that a match is reliable.
"""

from __future__ import annotations

import os
import re
from datetime import date

REVIEWED = "2026-10-25"

# runtime -> {release line -> end-of-life date}. Python/PHP/Ruby lines are "major.minor", Node.js lines are "major".
END_OF_LIFE: dict[str, dict[str, str]] = {
    "python": {"2.7": "2020-01-01", "3.5": "2020-09-13", "3.6": "2021-12-23", "3.7": "2023-06-27", "3.8": "2024-10-07", "3.9": "2025-10-31",
               "3.10": "2026-10-01"},
    "node": {"8": "2019-12-31", "10": "2021-04-30", "12": "2022-04-30", "14": "2023-04-30", "16": "2023-09-11", "17": "2022-06-01", "18": "2025-04-30",
             "19": "2023-06-01", "20": "2026-04-30", "21": "2024-06-01", "23": "2025-06-01", "25": "2026-06-01"},
    "php": {"7.2": "2020-11-30", "7.3": "2021-12-06", "7.4": "2022-11-28", "8.0": "2023-11-26", "8.1": "2025-12-31"},
    "ruby": {"2.7": "2023-03-31", "3.0": "2024-04-23", "3.1": "2025-03-31", "3.2": "2026-03-31"},
}
DISPLAY = {"python": "Python", "node": "Node.js", "php": "PHP", "ruby": "Ruby"}
_ALIASES = {"python": "python", "python3": "python", "cpython": "python", "node": "node", "nodejs": "node",
            "php": "php", "ruby": "ruby"}

_DOCKER_FROM = re.compile(r"^\s*FROM\s+(?:--platform=\S+\s+)?(?:[\w.\-]+/)*(python|node|php|ruby)[:@]v?(\d+(?:\.\d+)?)",
                          re.IGNORECASE)
_CI_VERSION = re.compile(r"\b(python|node|php|ruby)-version\s*:\s*(.+)$", re.IGNORECASE)
_NUMBER = re.compile(r"v?(\d+(?:\.\d+)?)(?:\.\d+)*")


def _line_of(rel: str) -> str:
    return os.path.basename(rel).lower()


def _line_key(runtime: str, version: str) -> str | None:
    """Release line of a version string, or None when it is not a plain version."""
    match = _NUMBER.fullmatch(version.strip().strip("\"'"))
    if not match:
        return None
    parts = match.group(0).lstrip("v").split(".")
    if runtime == "node":
        return parts[0]
    return ".".join(parts[:2]) if len(parts) > 1 else None


def scan_text(rel: str, text: str, today: date | None = None) -> list[tuple[int, str, str, str]]:
    """(line, runtime, version, end-of-life date) of every runtime in ``text`` that is already past its end of life."""
    today = today or date.today()
    name = _line_of(rel)
    found: list[tuple[int, str, str]] = []   # (line, runtime, raw version)
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if name == ".python-version":
            found.append((number, "python", re.sub(r"^cpython-", "", line)))
        elif name == "runtime.txt":
            match = re.match(r"python-(\d+\.\d+(?:\.\d+)?)", line)
            if match:
                found.append((number, "python", match.group(1)))
        elif name in (".nvmrc", ".node-version"):
            found.append((number, "node", line))
        elif name == ".tool-versions":
            parts = line.split()
            if len(parts) >= 2 and parts[0].lower() in _ALIASES:
                found.append((number, _ALIASES[parts[0].lower()], parts[1]))
        elif name == "dockerfile" or name.startswith("dockerfile.") or name.endswith(".dockerfile"):
            match = _DOCKER_FROM.match(raw)
            if match:
                found.append((number, match.group(1).lower(), match.group(2)))
        elif rel.lower().endswith((".yml", ".yaml")) and "/workflows/" in "/" + rel.lower():
            match = _CI_VERSION.search(raw.split("#", 1)[0])
            if match:
                for token in re.findall(r"[\"']?v?\d+(?:\.\d+)*[\"']?", match.group(2)):
                    found.append((number, match.group(1).lower(), token))
    def expired(runtime: str, version: str) -> str:
        end = END_OF_LIFE.get(runtime, {}).get(_line_key(runtime, version) or "", "")
        return end if end and date.fromisoformat(end) <= today else ""

    if rel.lower().endswith((".yml", ".yaml")):
        # A pipeline that also tests a supported release is checking compatibility, not running on a dead runtime.
        supported = {runtime for _n, runtime, version in found if not expired(runtime, version)}
        found = [item for item in found if item[1] not in supported]
    issues = []
    for number, runtime, version in found:
        end = expired(runtime, version)
        if end:
            issues.append((number, runtime, version.strip("\"'"), end))
    return issues
