"""Static detection of regular expressions prone to catastrophic backtracking (ReDoS).

User-supplied patterns (custom rules and allow-list values from ``.securerepo.toml``) run with Python's ``re``,
which has no timeout. A pattern such as ``(a+)+$`` hangs the scan on a 40-character input, so risky patterns are
rejected when the configuration is loaded, with an explanation.

The check is a conservative heuristic over the parsed pattern: it flags an unbounded repeat whose body can end
in another unbounded/optional repeat (``(a+)+``, ``(\\w+\\s?)*``, ``(.*)*``) and unbounded repeats over an
alternation with overlapping branches (``(a|a)*``, ``(a|ab)+``, ``(.|x)*``).
"""

from __future__ import annotations

from typing import Optional

try:  # Python 3.11+
    from re import _constants as _c, _parser as _p
except ImportError:  # pragma: no cover - Python 3.9 / 3.10
    import sre_constants as _c  # type: ignore
    import sre_parse as _p  # type: ignore

MAX_PATTERN_LENGTH = 1000
_REPEATS = tuple(getattr(_c, name) for name in ("MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT") if hasattr(_c, name))
_BROAD = tuple(getattr(_c, name) for name in ("ANY", "IN", "CATEGORY", "NOT_LITERAL") if hasattr(_c, name))
_ATOMIC = getattr(_c, "ATOMIC_GROUP", None)
BIG_BOUND = 1000


def _unbounded(av) -> bool:
    return av[1] == _c.MAXREPEAT or av[1] > BIG_BOUND


def _items(node):
    """Sub-pattern items of a SUBPATTERN / group body, whatever the Python version."""
    return list(node)


def _last_variable(sub) -> bool:
    """True when the body can end with a repeat that has no fixed length (so iterations can overlap)."""
    items = _items(sub)
    if not items:
        return False
    op, av = items[-1]
    if op in _REPEATS:
        return _unbounded(av) or av[0] == 0
    if op == _c.SUBPATTERN:
        return _last_variable(av[-1])
    if op == _c.BRANCH:
        return any(_last_variable(alt) for alt in av[1])
    return False


def _first(alt):
    items = _items(alt)
    if not items:
        return ("E", None)
    op, av = items[0]
    if op == _c.LITERAL:
        return ("L", av)
    if op == _c.SUBPATTERN:
        return _first(av[-1])
    if op in _BROAD:
        return ("B", None)
    if op in _REPEATS:
        return ("B", None)
    return ("?", None)


def _overlapping_branch(sub) -> bool:
    for op, av in _items(sub):
        if op == _c.BRANCH:
            firsts = [_first(alt) for alt in av[1]]
            literals = [f for kind, f in firsts if kind == "L"]
            if any(kind in ("B", "E") for kind, _ in firsts) or len(literals) != len(set(literals)):
                return True
        elif op == _c.SUBPATTERN and _overlapping_branch(av[-1]):
            return True
    return False


def _risk(sub) -> Optional[str]:
    for op, av in _items(sub):
        if op in _REPEATS:
            child = av[2]
            if _unbounded(av):
                if _last_variable(child):
                    return "nested quantifiers (a repeat whose body ends in another repeat)"
                if _overlapping_branch(child):
                    return "a repeated alternation whose branches overlap"
            found = _risk(child)
            if found:
                return found
        elif op == _c.SUBPATTERN:
            found = _risk(av[-1])
            if found:
                return found
        elif op == _c.BRANCH:
            for alt in av[1]:
                found = _risk(alt)
                if found:
                    return found
        elif op in (_c.ASSERT, _c.ASSERT_NOT):
            found = _risk(av[1])
            if found:
                return found
        elif _ATOMIC is not None and op == _ATOMIC:
            found = _risk(av)
            if found:
                return found
    return None


def check_pattern(pattern: str) -> Optional[str]:
    """Return a human readable reason when ``pattern`` is unsafe to run on untrusted input, else None."""
    if len(pattern) > MAX_PATTERN_LENGTH:
        return f"the pattern is longer than {MAX_PATTERN_LENGTH} characters"
    try:
        parsed = _p.parse(pattern)
    except Exception:  # invalid syntax is reported by the caller's own compile()
        return None
    reason = _risk(parsed)
    return f"possible catastrophic backtracking (ReDoS): {reason}" if reason else None
