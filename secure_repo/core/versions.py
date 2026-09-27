"""Version parsing and range matching for every supported ecosystem.

Used to resolve declared ranges (``^4.17.0``, ``>=2.0,<3``, ``~> 1.2``, ``[1.0,2.0)``...) to the
concrete release a package manager would install, when a project has no lockfile.
"""

from __future__ import annotations

import re
from typing import Callable, List, Optional, Sequence, Tuple

Key = Tuple
_VERSION_RE = re.compile(r"^\s*[vV=]?\s*(\d+(?:\.\d+)*)(.*)$")
_PRE_RE = re.compile(r"(?i)(a|alpha|b|beta|rc|c|pre|preview|dev|snapshot|m|milestone|canary|next|nightly)")


def parse(version: str) -> Optional[Key]:
    match = _VERSION_RE.match(str(version or ""))
    if not match:
        return None
    release = tuple(int(part) for part in match.group(1).split("."))
    release = release + (0,) * (6 - len(release)) if len(release) < 6 else release[:6]
    rest = match.group(2).strip()
    rest = rest.split("+", 1)[0]  # build metadata never affects ordering
    if not rest:
        return release + (2, ())
    tag = rest.lstrip("-._")
    if tag.lower().startswith(("post", "r", "p")) and not _PRE_RE.match(tag) or tag.lower() in ("final", "ga", "release"):
        return release + (3, _parts(tag))
    return release + (1, _parts(tag))


def _parts(tag: str) -> Tuple:
    items = []
    for part in re.findall(r"\d+|[A-Za-z]+", tag):
        items.append((0, int(part), "") if part.isdigit() else (1, 0, part.lower()))
    return tuple(items)


def is_prerelease(version: str) -> bool:
    key = parse(version)
    return bool(key) and key[6] == 1


def _release(version: str) -> List[int]:
    match = _VERSION_RE.match(version)
    return [int(p) for p in match.group(1).split(".")] if match else []


def _key_from(parts: Sequence[int]) -> Key:
    parts = tuple(parts) + (0,) * (6 - len(parts))
    return parts[:6] + (0, ())  # lowest possible key for that release (below pre-releases)


Predicate = Callable[[Key], bool]


def _cmp(op: str, version: str) -> Optional[Predicate]:
    target = parse(version)
    if target is None:
        return None
    if op in ("=", "==", "==="):
        return lambda k: k[:6] == target[:6] and (k[6:] == target[6:] or target[6] == 2)
    if op == "!=":
        return lambda k: k[:6] != target[:6]
    if op == ">=":
        return lambda k: k >= target
    if op == ">":
        return lambda k: k > target
    if op == "<=":
        return lambda k: k <= target or k[:6] == target[:6]
    if op == "<":
        upper = _key_from(_release(version))
        return lambda k: k < upper
    return None


def _between(lower: Sequence[int], upper: Sequence[int]) -> Predicate:
    low, high = _key_from(lower), _key_from(upper)
    return lambda k: low <= k < high


def _wildcard(spec: str) -> Optional[Predicate]:
    parts = re.split(r"\.", spec.strip().lstrip("=v"))
    fixed = []
    for part in parts:
        if part in ("x", "X", "*", ""):
            break
        if not part.isdigit():
            return None
        fixed.append(int(part))
    if not fixed:
        return lambda k: True
    upper = fixed[:-1] + [fixed[-1] + 1]
    return _between(fixed, upper)


def _caret(version: str) -> Optional[Predicate]:
    parts = _release(version)
    if not parts:
        return None
    lower_key = parse(version)
    specified = len(re.match(r"\s*v?([\d.x*]+)", version).group(1).strip(".").split("."))
    padded = parts + [0] * (3 - len(parts))
    if padded[0] > 0 or specified == 1:
        upper = [padded[0] + 1]
    elif padded[1] > 0 or specified == 2:
        upper = [0, padded[1] + 1]
    else:
        upper = [0, 0, padded[2] + 1]
    high = _key_from(upper)
    return lambda k: lower_key <= k < high


def _tilde(version: str, composer: bool = False) -> Optional[Predicate]:
    parts = _release(version)
    if not parts:
        return None
    lower_key = parse(version)
    if composer and len(parts) >= 2:
        upper = parts[:-2] + [parts[-2] + 1]
    elif len(parts) == 1:
        upper = [parts[0] + 1]
    else:
        upper = [parts[0], parts[1] + 1]
    high = _key_from(upper)
    return lambda k: lower_key <= k < high


def _pessimistic(version: str) -> Optional[Predicate]:
    """RubyGems ``~>`` and PEP 440 ``~=``: the last given component may grow."""
    parts = _release(version)
    if len(parts) < 2:
        return _cmp(">=", version)
    lower_key = parse(version)
    upper = parts[:-2] + [parts[-2] + 1]
    high = _key_from(upper)
    return lambda k: lower_key <= k < high


def _all(predicates: List[Predicate]) -> Predicate:
    return lambda k: all(p(k) for p in predicates)


def _any(alternatives: List[Predicate]) -> Predicate:
    return lambda k: any(p(k) for p in alternatives)


_COMPARATOR = re.compile(r"^(~>|~=|===|==|!=|>=|<=|>|<|=|\^|~)?\s*(.+)$")


def _simple(term: str, ecosystem: str) -> Optional[Predicate]:
    term = term.strip()
    if not term or term in ("*", "x", "X", "latest", "any", "next"):
        return lambda k: True
    match = _COMPARATOR.match(term)
    if not match:
        return None
    op, version = match.group(1) or "", match.group(2).strip()
    if re.search(r"(^|\.)[xX*](\.|$)", version) and op in ("", "=", "=="):
        return _wildcard(version)
    if op == "^":
        return _caret(version)
    if op == "~":
        return _tilde(version, composer=ecosystem == "Packagist")
    if op in ("~>", "~="):
        return _pessimistic(version)
    if op == "" and ecosystem in ("crates.io",):
        return _caret(version)
    if op == "" and ecosystem == "NuGet":
        return _cmp(">=", version)
    return _cmp(op or "==", version)


def _maven_interval(spec: str) -> Optional[Predicate]:
    intervals = re.findall(r"([\[(])\s*([^,\])]*)\s*(?:,\s*([^\])]*))?\s*([\])])", spec)
    if not intervals:
        return None
    alternatives = []
    for opening, low, high, closing in intervals:
        if "," not in spec[spec.find(opening):] and not high and low:
            alternatives.append(_cmp("==", low))
            continue
        checks = []
        if low:
            checks.append(_cmp(">=" if opening == "[" else ">", low))
        if high:
            checks.append(_cmp("<=" if closing == "]" else "<", high))
        checks = [c for c in checks if c]
        alternatives.append(_all(checks) if checks else (lambda k: True))
    return _any(alternatives)


def matcher(spec: str, ecosystem: str) -> Optional[Predicate]:
    """Build a predicate over parsed version keys, or None when the spec cannot be understood."""
    spec = (spec or "").strip()
    if ecosystem in ("Maven", "NuGet") and spec[:1] in ("[", "("):
        return _maven_interval(spec)
    if ecosystem == "Maven" and spec:
        return _cmp("==", spec)
    if ecosystem == "Go":
        return _cmp("==", spec)
    alternatives = re.split(r"\s*\|\|?\s*", spec) if ecosystem in ("npm", "Packagist") else [spec]
    built = []
    for alternative in alternatives:
        hyphen = re.match(r"^\s*(\S+)\s+-\s+(\S+)\s*$", alternative)
        if hyphen:
            low, high = _cmp(">=", hyphen.group(1)), _cmp("<=", hyphen.group(2))
            if low and high:
                built.append(_all([low, high]))
            continue
        if ecosystem in ("PyPI", "crates.io", "RubyGems"):
            terms = [t for t in alternative.split(",")]
        elif ecosystem == "Packagist":
            terms = re.split(r"[\s,]+", alternative)
        else:
            terms = re.split(r"\s+(?=[<>=~^!])|\s*,\s*", alternative)
        terms = [t.strip() for t in terms if t.strip()]
        if not terms:
            built.append(lambda k: True)
            continue
        if ecosystem == "PyPI" and len(terms) == 1 and terms[0].startswith("==") and terms[0].endswith(".*"):
            built.append(_wildcard(terms[0][2:]))
            continue
        predicates = []
        for term in terms:
            if ecosystem == "PyPI" and term.startswith(("==", "!=")) and term.endswith(".*"):
                wildcard = _wildcard(term[2:])
                predicate = wildcard if term.startswith("==") else (lambda w: (lambda k: not w(k)))(wildcard)
            else:
                predicate = _simple(term, ecosystem)
            if predicate is None:
                return None
            predicates.append(predicate)
        built.append(_all(predicates))
    return _any(built) if built else None


def resolve(spec: str, versions: Sequence[str], ecosystem: str) -> Tuple[Optional[str], Optional[str]]:
    """Return (version the package manager would pick, lowest version admitted) for a range."""
    predicate = matcher(spec, ecosystem)
    if predicate is None:
        return None, None
    allow_pre = bool(re.search(r"\d[-.]?(?:a|b|rc|alpha|beta|pre|dev)", spec or "", re.I))
    candidates = []
    for version in versions:
        key = parse(version)
        if key is None or (key[6] == 1 and not allow_pre):
            continue
        if predicate(key):
            candidates.append((key, version))
    if not candidates:
        return None, None
    candidates.sort(key=lambda item: item[0])
    lowest, highest = candidates[0][1], candidates[-1][1]
    chosen = lowest if ecosystem == "NuGet" else highest  # NuGet resolves the lowest applicable version
    return chosen, lowest
