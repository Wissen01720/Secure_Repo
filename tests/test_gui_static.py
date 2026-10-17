"""Static guard for the GUI front end (C-23): markup assembled by concatenation must escape every dynamic value."""
import glob
import os
import re

STATIC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "secure_repo", "gui", "static")

# Operands that are known to return safe markup or plain numbers.
SAFE_CALLS = ("esc(", "SR.esc(", "SR.sevTag(", "SR.num(", "SR.bytes(", "SR.clock(", "SR.trunc(",
              "ring(", "vulnTable(", "refsHTML(", "A.ring(", "A.vulnTable(", "A.refsHTML(")      # the last three build markup and are checked as well (return '<...)
SAFE_NAMES = {"html", "risk", "adv"}   # accumulators / locals whose own assignments are checked by this test
ARROW_MAP = re.compile(r".+?\.map\(\s*\(?[\w, ]*\)?\s*=>\s*(.+)\)\.join\([^)]*\)", re.DOTALL)
STRING_LITERAL = re.compile(r"'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\"")


def split_statement(source, start):
    """Return the text of the statement that begins at `start`, ending at the first top-level ';'."""
    depth, quote, i = 0, None, start
    while i < len(source):
        ch = source[i]
        if quote:
            if ch == "\\":
                i += 1
            elif ch == quote:
                quote = None
        elif ch in "'\"`":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth < 0:
                return source[start:i]
        elif ch == ";" and depth == 0:
            return source[start:i]
        i += 1
    return source[start:]


def split_plus(expression, separator="+"):
    """Split on top-level operators ('+' or '||'), respecting strings and brackets."""
    parts, depth, quote, current = [], 0, None, ""
    i = 0
    while i < len(expression):
        ch = expression[i]
        if quote:
            current += ch
            if ch == "\\":
                i += 1
                current += expression[i]
            elif ch == quote:
                quote = None
        elif ch in "'\"`":
            quote = ch
            current += ch
        elif ch in "([{":
            depth += 1
            current += ch
        elif ch in ")]}":
            depth -= 1
            current += ch
        elif depth == 0 and expression.startswith(separator, i):
            parts.append(current.strip())
            current = ""
            i += len(separator) - 1
        else:
            current += ch
        i += 1
    parts.append(current.strip())
    return [p for p in parts if p]


def unsafe_operands(expression):
    bad = []
    for operand in split_plus(expression):
        text = operand.strip()
        while text.startswith("(") and text.endswith(")"):       # (cond ? 'a' : esc(x))
            text = text[1:-1].strip()
        if STRING_LITERAL.fullmatch(text) or text in SAFE_NAMES:
            continue
        if text.startswith(SAFE_CALLS) or text.endswith(".length") or text.startswith("badges.join("):
            continue
        alternatives = split_plus(text, "||")
        if len(alternatives) > 1 and not unsafe_operands(" + ".join(alternatives)):
            continue
        mapped = ARROW_MAP.fullmatch(text)
        if mapped and not unsafe_operands(mapped.group(1)):
            continue
        branches = split_plus(text, "?")
        if len(branches) == 2:
            options = split_plus(branches[1], ":")
            if len(options) == 2 and not unsafe_operands(options[0]) and not unsafe_operands(options[1]):
                continue
        bad.append(operand.strip())
    return bad


def markup_statements(source):
    for match in re.finditer(r"SR\.setHTML\(\s*[\w.]+\s*,", source):
        yield match.start(), split_statement(source, match.end())
    for match in re.finditer(r"(?<![\w.])html\s*\+?=\s*(?!=)", source):
        yield match.start(), split_statement(source, match.end())
    for match in re.finditer(r"const (?:risk|adv)\s*=\s*|badges\.push\(|return\s+(?=['\"]<)", source):
        yield match.start(), split_statement(source, match.end())


def test_markup_concatenation_always_escapes_dynamic_values():
    problems = []
    for path in sorted(glob.glob(os.path.join(STATIC, "*.js"))):
        with open(path, encoding="utf-8") as handle:
            source = handle.read()
        for offset, expression in markup_statements(source):
            for operand in unsafe_operands(expression):
                line = source.count("\n", 0, offset) + 1
                problems.append(f"{os.path.basename(path)}:{line}: {operand[:90]}")
    assert not problems, "dynamic value concatenated into markup without esc():\n" + "\n".join(problems)


def test_the_guard_itself_catches_an_unescaped_value():
    assert unsafe_operands("'<b>' + name + '</b>'") == ["name"]
    assert unsafe_operands("'<b>' + esc(name) + '</b>'") == []
    assert unsafe_operands("'<i>' + (x ? esc(a) : '') + '</i>'") == []
    assert unsafe_operands("'<i>' + (x ? a : '') + '</i>'") != []
