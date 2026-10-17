"""Structural checks for web application configuration written in JavaScript / TypeScript.

Some weaknesses are an *absent* setting, which no line-by-line pattern can see: an ``express-session`` call without
``cookie.secure`` is vulnerable precisely because the option is not there (or is commented out). These checks read
the comment-free source and look at the whole option object.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

RULE_COOKIE_FLAGS = "SR-JS-027"
RULE_EXPRESS_CSRF = "SR-JS-028"
RULE_DJANGO_CSRF = "SR-PY-025"

_SESSION_CALL = re.compile(r"\b(?:session|cookieSession|cookie_session)\s*\(\s*\{")
_COOKIE_OPTION = re.compile(r"\bcookie\s*:\s*\{")
_RES_COOKIE = re.compile(r"\bres\.cookie\s*\(")
_FALSE_FLAG = re.compile(r"\b(secure|httpOnly)\s*:\s*false\b")
_SECURE_SET = re.compile(r"\bsecure\s*:\s*(?!false\b)\S")
_SAMESITE_NONE = re.compile(r"\bsameSite\s*:\s*['\"]none['\"]", re.I)


def _block(text: str, brace: int) -> Optional[Tuple[int, int]]:
    """(start, end) of the {...} block whose opening brace is at ``brace``; strings are skipped."""
    depth, quote, i = 0, None, brace
    while i < len(text):
        ch = text[i]
        if quote:
            if ch == "\\":
                i += 1
            elif ch == quote:
                quote = None
        elif ch in "'\"`":
            quote = ch
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return brace, i + 1
        i += 1
    return None


def cookie_flag_issues(text: str) -> List[Tuple[int, str]]:
    """(offset, detail) for every session / cookie configuration with weak flags."""
    issues: List[Tuple[int, str]] = []
    covered: List[Tuple[int, int]] = []

    for call in _SESSION_CALL.finditer(text):
        span = _block(text, call.end() - 1)
        if span is None:
            continue
        covered.append(span)
        options = text[span[0]:span[1]]
        cookie = _COOKIE_OPTION.search(options)
        if cookie is None:
            issues.append((call.start(), "The session is created without a cookie configuration: the cookie is sent "
                                         "without the Secure flag and can travel over plain HTTP."))
            continue
        inner = _block(options, cookie.end() - 1)
        flags = options[inner[0]:inner[1]] if inner else ""
        problems = []
        if not _SECURE_SET.search(flags):
            problems.append("'secure' is not enabled (or its line is commented out)")
        if re.search(r"\bhttpOnly\s*:\s*false\b", flags):
            problems.append("'httpOnly' is false, so scripts can read the session cookie")
        if _SAMESITE_NONE.search(flags) and not _SECURE_SET.search(flags):
            problems.append("'sameSite: none' without 'secure' is rejected or ignored by browsers")
        if problems:
            issues.append((call.start() + cookie.start(), "Session cookie: " + "; ".join(problems) + "."))

    for option in _COOKIE_OPTION.finditer(text):
        if any(start <= option.start() < end for start, end in covered):
            continue
        span = _block(text, option.end() - 1)
        if span is None:
            continue
        for flag in _FALSE_FLAG.finditer(text[span[0]:span[1]]):
            issues.append((option.start() + flag.start(), f"Cookie option '{flag.group(1)}: false' disables a "
                                                         f"browser protection for this cookie."))

    for call in _RES_COOKIE.finditer(text):
        end = text.find(";", call.end())
        arguments = text[call.end():end if end != -1 else call.end() + 400]
        for flag in _FALSE_FLAG.finditer(arguments):
            issues.append((call.start(), f"res.cookie() is called with '{flag.group(1)}: false'."))
    return sorted(set(issues))


_EXPRESS = re.compile(r"""require\(\s*['"]express['"]\s*\)|from\s+['"]express['"]""")
_SESSION_USE = re.compile(r"\b(?:session|cookieSession|cookie_session)\s*\(\s*\{")
_STATE_CHANGING = re.compile(r"\b(?:app|router|server)\.(?:post|put|patch|delete)\s*\(")
_CSRF_MARKERS = re.compile(r"(?i)csurf|csrf|xsrf|lusca|doublecsrf|crumb")


def express_facts(text: str) -> Dict:
    """What one JavaScript file says about the CSRF posture of an Express application (see express_csrf_findings)."""
    session = _SESSION_USE.search(text)
    return {"express": bool(_EXPRESS.search(text)), "session_offset": session.start() if session else -1,
            "state_routes": _STATE_CHANGING.search(text) is not None, "csrf": _CSRF_MARKERS.search(text) is not None}


def express_csrf_findings(facts: List[Dict]) -> List[Dict]:
    """Project-level: cookie sessions + state-changing routes, and no CSRF middleware in any file.

    The session setup, the routes and the middleware usually live in different files, so the verdict needs every
    file's facts. Returns at most one entry: the file and line where the session is created.
    """
    if any(f["csrf"] for f in facts) or not any(f["state_routes"] for f in facts):
        return []
    for fact in facts:
        if fact["express"] and fact["session_line"]:
            return [{"file": fact["file"], "line": fact["session_line"], "snippet": fact["snippet"],
                     "detail": "The application uses cookie sessions and has state-changing routes, but no file of the "
                               "project mentions CSRF protection (csurf, csrf-csrf, lusca...). If the middleware comes "
                               "from somewhere this scan cannot see, this is a false alarm."}]
    return []


_DJANGO_MIDDLEWARE = re.compile(r"(?m)^\s*(MIDDLEWARE(?:_CLASSES)?)\s*=\s*[\[(]")


def django_csrf_issues(text: str) -> List[Tuple[int, str]]:
    """A Django MIDDLEWARE list that has sessions but no CsrfViewMiddleware."""
    match = _DJANGO_MIDDLEWARE.search(text)
    if match is None or "django" not in text.lower():
        return []
    end = text.find("]", match.end())
    block = text[match.start():end if end != -1 else len(text)]
    if "SessionMiddleware" in block and "CsrfViewMiddleware" not in block:
        return [(match.start(1), "MIDDLEWARE has SessionMiddleware but not django.middleware.csrf.CsrfViewMiddleware.")]
    return []
