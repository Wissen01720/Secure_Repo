"""Lexical masking: blank out comments and string contents while preserving offsets.

Two views are produced for programming languages:

* ``no_comments`` - comments replaced by spaces, strings untouched;
* ``code``        - comments *and* string interiors replaced by spaces. String delimiters are
  kept (so rules can still see that a literal exists) and template-literal expressions such as
  ``${user}`` / ``#{user}`` remain visible because they are real code.

Every masked character is replaced by a space and newlines are preserved, so offsets and line
numbers are identical to the original text. That lets the pattern engine skip matches inside
comments, docstrings and messages - including multi-line ones - without losing positions.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

C_LIKE = {"Java", "Kotlin", "Scala", "Groovy", "Gradle", "C#", "C", "C++", "Objective-C", "Go", "Rust", "Swift",
          "Dart", "Solidity", "F#"}
JS_LIKE = {"JavaScript", "TypeScript"}

_C_PATTERN = re.compile(
    r'(?P<lc>//[^\n]*)'
    r'|(?P<bc>/\*.*?(?:\*/|\Z))'
    r'|(?P<tq>"""(?:.|\n)*?(?:"""|\Z))'
    r'|(?P<dq>@?\$?"(?:\\.|[^"\\\n])*"?)'
    r"|(?P<sq>'(?:\\.|[^'\\\n])*'?)", re.S)
_GO_PATTERN = re.compile(
    r'(?P<lc>//[^\n]*)'
    r'|(?P<bc>/\*.*?(?:\*/|\Z))'
    r'|(?P<raw>`[^`]*`?)'
    r'|(?P<dq>"(?:\\.|[^"\\\n])*"?)'
    r"|(?P<sq>'(?:\\.|[^'\\\n])*'?)", re.S)
_RUST_PATTERN = re.compile(
    r'(?P<lc>//[^\n]*)'
    r'|(?P<bc>/\*.*?(?:\*/|\Z))'
    r'|(?P<dq>b?"(?:\\.|[^"\\])*"?)'
    r"|(?P<sq>b?'(?:\\.|[^'\\\n])')", re.S)
_JS_PATTERN = re.compile(
    r'(?P<lc>//[^\n]*)'
    r'|(?P<bc>/\*.*?(?:\*/|\Z))'
    r'|(?P<tpl>`(?:\\.|\$\{(?:[^{}`]|\{[^{}]*\})*\}|[^\\`])*`?)'
    r'|(?P<dq>"(?:\\.|[^"\\\n])*"?)'
    r"|(?P<sq>'(?:\\.|[^'\\\n])*'?)", re.S)
_PY_PATTERN = re.compile(
    r'(?P<lc>\#[^\n]*)'
    r'|(?P<tq>(?<![\w])[rRbBuUfF]{0,2}(?:\'\'\'(?:.|\n)*?(?:\'\'\'|\Z)|"""(?:.|\n)*?(?:"""|\Z)))'
    r'|(?P<dq>(?<![\w])[rRbBuUfF]{0,2}"(?:\\.|[^"\\\n])*"?)'
    r"|(?P<sq>(?<![\w])[rRbBuUfF]{0,2}'(?:\\.|[^'\\\n])*'?)", re.S)
_RUBY_PATTERN = re.compile(
    r'(?P<bc>^=begin\b.*?(?:^=end\b|\Z))'
    r'|(?P<dq>"(?:\\.|\#\{[^}]*\}|[^"\\])*"?)'
    r"|(?P<sq>'(?:\\.|[^'\\])*'?)"
    r'|(?P<lc>\#(?!\{)[^\n]*)', re.S | re.M)
_PHP_PATTERN = re.compile(
    r'(?P<lc>(?://|\#(?!\[))[^\n]*)'
    r'|(?P<bc>/\*.*?(?:\*/|\Z))'
    r'|(?P<dq>"(?:\\.|[^"\\])*"?)'
    r"|(?P<sq>'(?:\\.|[^'\\])*'?)", re.S)

_INTERPOLATION = {
    "tpl": re.compile(r"\$\{(?:[^{}]|\{[^{}]*\})*\}"),
    "ruby": re.compile(r"\#\{[^}]*\}"),
}


def family(language: str) -> Optional[str]:
    if language in JS_LIKE:
        return "js"
    if language == "Python":
        return "python"
    if language == "Ruby":
        return "ruby"
    if language == "PHP":
        return "php"
    if language == "Go":
        return "go"
    if language == "Rust":
        return "rust"
    if language in C_LIKE:
        return "c"
    return None


_PATTERNS = {"js": _JS_PATTERN, "python": _PY_PATTERN, "ruby": _RUBY_PATTERN, "php": _PHP_PATTERN,
             "go": _GO_PATTERN, "rust": _RUST_PATTERN, "c": _C_PATTERN}


def _blank(chars: List[str], start: int, end: int, keep: Optional[List[Tuple[int, int]]] = None) -> None:
    keep = keep or []
    for index in range(start, end):
        if chars[index] == "\n":
            continue
        if any(a <= index < b for a, b in keep):
            continue
        chars[index] = " "


def _string_interior(text: str, start: int, end: int) -> Tuple[int, int]:
    """Return the span between the opening and closing delimiters of a string literal."""
    segment = text[start:end]
    prefix = len(segment) - len(segment.lstrip("rRbBuUfF@$"))
    body = segment[prefix:]
    for delimiter in ('"""', "'''", '"', "'", "`"):
        if body.startswith(delimiter):
            open_len = prefix + len(delimiter)
            close_len = len(delimiter) if len(body) >= 2 * len(delimiter) and body.endswith(delimiter) else 0
            return start + open_len, end - close_len
    return start, end


def mask(text: str, language: str) -> Optional[Dict[str, str]]:
    """Return {'code': ..., 'no_comments': ...} or None when the language is not masked."""
    fam = family(language)
    if fam is None:
        return None
    pattern = _PATTERNS[fam]
    code = list(text)
    no_comments = list(text)
    for match in pattern.finditer(text):
        kind = match.lastgroup
        start, end = match.span()
        if kind in ("lc", "bc"):
            _blank(code, start, end)
            _blank(no_comments, start, end)
            continue
        inner_start, inner_end = _string_interior(text, start, end)
        keep: List[Tuple[int, int]] = []
        if kind == "tpl":
            keep = [(m.start(), m.end()) for m in _INTERPOLATION["tpl"].finditer(text, inner_start, inner_end)]
        elif fam == "ruby" and kind == "dq":
            keep = [(m.start(), m.end()) for m in _INTERPOLATION["ruby"].finditer(text, inner_start, inner_end)]
        _blank(code, inner_start, inner_end, keep)
    return {"code": "".join(code), "no_comments": "".join(no_comments)}


def string_spans(text: str, language: str) -> List[Tuple[int, int]]:
    """Spans (start, end) of string literal interiors - used to test whether a match is inside a string."""
    fam = family(language)
    if fam is None:
        return []
    spans = []
    for match in _PATTERNS[fam].finditer(text):
        if match.lastgroup not in ("lc", "bc"):
            spans.append(_string_interior(text, *match.span()))
    return spans
