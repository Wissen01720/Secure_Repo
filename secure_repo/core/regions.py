"""Structural regions of a file: where a pattern match is actually meaningful.

A regular expression sees lines, not structure. Some patterns only matter in one place: a GitHub Actions
expression such as ``${{ github.event.pull_request.title }}`` is an injection only when it is expanded inside a
shell script (``run:``) or a ``github-script`` body (``script:``). The same expression under ``env:`` is the
mitigation that the rule itself recommends.
"""

from __future__ import annotations

import re
from typing import Callable, Dict, Set

_SCRIPT_KEY = re.compile(r"^(?P<indent>\s*)(?:-\s+)?(?P<key>run|script)\s*:(?P<value>.*)$")


def ci_script_lines(text: str) -> Set[int]:
    """1-based numbers of the lines that belong to the value of a ``run:`` or ``script:`` key.

    Handles the inline form (``run: echo ...``), block scalars (``run: |`` / ``>``) and plain scalars continued on
    more-indented lines. No YAML parser is needed: a value ends at the first non-blank line that is not indented
    deeper than its key.
    """
    lines = text.split("\n")
    inside: Set[int] = set()
    index = 0
    while index < len(lines):
        match = _SCRIPT_KEY.match(lines[index])
        if not match:
            index += 1
            continue
        key_column = match.start("key")
        if match.group("value").strip():
            inside.add(index + 1)
        cursor = index + 1
        while cursor < len(lines):
            line = lines[cursor]
            if line.strip():
                if len(line) - len(line.lstrip(" ")) <= key_column:
                    break
                inside.add(cursor + 1)
            cursor += 1
        index = max(cursor, index + 1)
    return inside


_PRE_CODE_OPEN = re.compile(r"<(pre|code)\b[^>]*>", re.I)


def markup_example_lines(text: str) -> Set[int]:
    """1-based numbers of the lines inside ``<pre>`` / ``<code>`` blocks (documentation examples in HTML)."""
    inside: Set[int] = set()
    for match in _PRE_CODE_OPEN.finditer(text):
        closing = re.compile(r"</" + match.group(1) + r"\s*>", re.I).search(text, match.end())
        end = closing.start() if closing else match.end()
        first = text.count("\n", 0, match.end()) + 1
        last = text.count("\n", 0, end) + 1
        inside.update(range(first, last + 1))
    return inside


REGIONS: Dict[str, Callable[[str], Set[int]]] = {
    "ci-scripts": ci_script_lines,
}
