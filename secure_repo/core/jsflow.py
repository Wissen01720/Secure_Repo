"""Lightweight data-flow analysis for JavaScript / TypeScript.

Works on the lexically masked source (comments and string contents blanked, template
expressions kept), so it never reacts to text inside comments or strings. It:

* collects declarations/assignments (including destructuring) and propagates taint from
  untrusted sources (``req.query``, ``location.hash``, ``event.data``...) through variables;
* inspects the arguments of dangerous sinks and classifies them as *constant* (not
  exploitable - the pattern finding is discarded), *tainted* (escalated, with a data-flow
  trace) or *dynamic* (kept at its default severity);
* recognises sanitizers (``encodeURIComponent``, ``DOMPurify.sanitize``, ``parseInt``...).
"""

from __future__ import annotations

import bisect
import re
from dataclasses import dataclass, field

SERVER_SOURCE = r"\b(?:req|request)\.(?:query|params|body|headers|cookies|originalUrl|url|path|files?)\b|" \
                r"\bctx\.(?:query|params|request\.(?:body|query))\b|\bprocess\.argv\b"
CLIENT_SOURCE = r"\b(?:window\.)?location\.(?:hash|search|href|pathname)\b|\bdocument\.(?:URL|documentURI|referrer|" \
                r"cookie|baseURI)\b|\bwindow\.name\b|\b(?:event|evt|e|msg|message)\.data\b|" \
                r"\bnew\s+URLSearchParams\s*\(|\b(?:localStorage|sessionStorage)\.getItem\b"
SOURCE_RE = re.compile(f"(?:{SERVER_SOURCE})|(?:{CLIENT_SOURCE})")
SERVER_SOURCE_RE = re.compile(SERVER_SOURCE)
SANITIZER_RE = re.compile(
    r"^\s*(?:await\s+)?(?:parseInt|parseFloat|Number|Boolean|Math\.\w+|encodeURIComponent|encodeURI|escape\w*|"
    r"DOMPurify\.sanitize|sanitize\w*|validator\.\w+|xss|he\.(?:encode|escape)|path\.basename|JSON\.stringify|"
    r"crypto\.\w+)\s*\(")
DECL_RE = re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::\s*[\w<>\[\]|, .]+?)?\s*=(?![=>])")
DESTRUCT_RE = re.compile(r"\b(?:const|let|var)\s*\{([^}]*)\}\s*(?::[^=]+)?=(?![=>])")
ASSIGN_RE = re.compile(r"(?<![\w$.])([A-Za-z_$][\w$]*)\s*\+?=(?![=>])")
CHILD_PROCESS_RE = re.compile(r"child_process|\bexeca\b|\bshelljs\b")

# (rule, regex, argument mode, server-only)
SINKS = [
    ("SR-JS-001", re.compile(r"(?<![\w$.])eval\s*\("), "arg0", False),
    ("SR-JS-001", re.compile(r"\bnew\s+Function\s*\("), "all", False),
    ("SR-JS-009", re.compile(r"\bset(?:Timeout|Interval)\s*\("), "arg0", False),
    ("SR-JS-002", re.compile(r"\.(?:innerHTML|outerHTML)\s*\+?=(?!=)"), "rhs", False),
    ("SR-JS-002", re.compile(r"\.insertAdjacentHTML\s*\("), "arg1", False),
    ("SR-JS-003", re.compile(r"\bdocument\.write(?:ln)?\s*\("), "all", False),
    ("SR-JS-004", re.compile(r"dangerouslySetInnerHTML\s*=\s*\{\{\s*__html\s*:"), "html", False),
    # exec/spawn as free functions or on child_process-like objects - never RegExp.prototype.exec
    ("SR-JS-007", re.compile(r"(?:(?<![\w$.])|(?<=child_process\.)|(?<=\bcp\.)|(?<=childProcess\.)|(?<=\bproc\.))"
                             r"(?:exec|execSync|execa|execaSync)\s*\("), "arg0", True),
    ("SR-JS-007", re.compile(r"(?:(?<![\w$.])|(?<=child_process\.)|(?<=\bcp\.)|(?<=childProcess\.))"
                             r"spawn(?:Sync)?\s*\("), "arg0", True),
    ("SR-JS-011", re.compile(r"\.(?:query|execute|raw|whereRaw|\$queryRawUnsafe|\$executeRawUnsafe)\s*\("), "arg0", False),
    ("SR-JS-016", re.compile(r"\b(?:fs\.)?(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync|unlink|"
                             r"unlinkSync|appendFile)\s*\(|\bres\.(?:sendFile|download)\s*\("), "arg0", True),
    ("SR-JS-017", re.compile(r"\b(?:axios(?:\.(?:get|post|put|delete|request|head|patch))?|fetch|"
                             r"(?:got|needle)(?:\.(?:get|post|put|delete|request|head|patch))?|"
                             r"superagent\.\w+|https?\.(?:get|request))\s*\("), "arg0", True),
    ("SR-JS-018", re.compile(r"\bres\.redirect\s*\("), "last", True),
    ("SR-JS-023", re.compile(r"\bres\.(?:send|write|end)\s*\("), "arg0", True),
    ("SR-JS-024", re.compile(r"\bnew\s+RegExp\s*\("), "arg0", False),
]
TAINTED_SEVERITY = {"SR-JS-001": "critical", "SR-JS-002": "high", "SR-JS-003": "high", "SR-JS-004": "high",
                    "SR-JS-008": "critical", "SR-JS-009": "high", "SR-JS-011": "critical", "SR-JS-016": "high",
                    "SR-JS-017": "high", "SR-JS-018": "medium", "SR-JS-023": "medium", "SR-JS-024": "medium"}
# Sinks that are only reported when tainted (their dynamic use is normal).
TAINT_ONLY = {"SR-JS-016", "SR-JS-017", "SR-JS-018", "SR-JS-023", "SR-JS-024"}
HANDLED_RULES = {"SR-JS-001", "SR-JS-002", "SR-JS-003", "SR-JS-004", "SR-JS-007", "SR-JS-008", "SR-JS-009",
                 "SR-JS-011", "SR-JS-016", "SR-JS-017", "SR-JS-018"}
FUNCTION_ARG_RE = re.compile(r"^\s*(?:async\s+)?(?:function\b|\(?[\w$,\s]*\)?\s*=>)")
CONSTANT_RE = re.compile(r"""^[\s'"`+0-9.,()\[\]{}:]*$|^\s*(?:true|false|null|undefined)\s*$""")


@dataclass
class Origin:
    label: str
    line: int
    server: bool
    steps: list[tuple[int, str]] = field(default_factory=list)
    scope: tuple[int, int] = (0, 1 << 60)   # function body where the tainted variable lives


@dataclass
class Decision:
    kind: str                 # constant | tainted | dynamic
    rule_id: str
    line: int
    severity: str | None = None
    flow: list[dict] = field(default_factory=list)
    detail: str = ""


class JsFlowAnalyzer:
    def __init__(self, original: str, code: str):
        self.original = original
        self.code = code
        self.lines = original.split("\n")
        self.newlines = [m.start() for m in re.finditer("\n", code)]
        self.tainted: dict[str, list[Origin]] = {}
        self.uses_child_process = bool(CHILD_PROCESS_RE.search(original))
        self.suppressed: dict[str, int] = {}
        self.functions = self._function_bodies()

    def _function_bodies(self) -> list[tuple[int, int]]:
        """Spans of function bodies ({...} preceded by ')' or '=>'), used as variable scopes."""
        spans: list[tuple[int, int]] = []
        stack: list[tuple[int, bool]] = []
        for index, char in enumerate(self.code):
            if char == "{":
                before = self.code[max(0, index - 40):index].rstrip()
                stack.append((index, before.endswith(")") or before.endswith("=>")))
            elif char == "}" and stack:
                start, is_function = stack.pop()
                if is_function:
                    spans.append((start, index))
        return spans

    def _scope_of(self, offset: int) -> tuple[int, int]:
        best = (0, 1 << 60)
        for start, end in self.functions:
            if start <= offset <= end and (end - start) < (best[1] - best[0]):
                best = (start, end)
        return best

    def _line(self, offset: int) -> int:
        return bisect.bisect_right(self.newlines, offset - 1) + 1 if offset else 1

    def _code_line(self, line: int) -> str:
        return self.lines[line - 1].strip()[:200] if 0 < line <= len(self.lines) else ""

    # ------------------------------------------------------------------ extraction helpers
    def _statement_end(self, start: int) -> int:
        depth = 0
        limit = min(len(self.code), start + 600)
        index = start
        while index < limit:
            char = self.code[index]
            if char in "([{":
                depth += 1
            elif char in ")]}":
                if depth == 0:
                    return index
                depth -= 1
            elif depth == 0 and char in ";\n":
                return index
            index += 1
        return index

    def _call_args(self, open_paren: int) -> list[str]:
        depth = 0
        args: list[str] = []
        current = open_paren + 1
        index = open_paren
        limit = min(len(self.code), open_paren + 1500)
        while index < limit:
            char = self.code[index]
            if char in "([{":
                depth += 1
            elif char in ")]}":
                depth -= 1
                if depth == 0:
                    args.append(self.code[current:index])
                    return [a for a in args if a.strip() or len(args) == 1]
            elif char == "," and depth == 1:
                args.append(self.code[current:index])
                current = index + 1
            index += 1
        args.append(self.code[current:limit])
        return args

    # ------------------------------------------------------------------ taint
    def _refs_taint(self, expression: str, position: int) -> Origin | None:
        match = SOURCE_RE.search(expression)
        if match:
            label = re.sub(r"\s+", " ", match.group(0).strip().rstrip("("))
            return Origin(label, -1, bool(SERVER_SOURCE_RE.search(match.group(0))))
        for name, origins in self.tainted.items():
            visible = [o for o in origins if o.scope[0] <= position <= o.scope[1]]
            if visible and re.search(r"(?<![\w$.])" + re.escape(name) + r"(?![\w$])", expression):
                return visible[0]
        return None

    def _collect_taint(self) -> None:
        assignments: list[tuple[list[str], str, int, int]] = []
        for match in DECL_RE.finditer(self.code):
            end = self._statement_end(match.end())
            assignments.append(([match.group(1)], self.code[match.end():end], self._line(match.start()), match.start()))
        for match in DESTRUCT_RE.finditer(self.code):
            names = [re.split(r"[:=]", part.strip())[-1].strip() if ":" in part else part.split("=")[0].strip()
                     for part in match.group(1).split(",")]
            names = [n.lstrip(".") for n in names if re.fullmatch(r"\.{0,3}[A-Za-z_$][\w$]*", n or "")]
            end = self._statement_end(match.end())
            assignments.append((names, self.code[match.end():end], self._line(match.start()), match.start()))
        for match in ASSIGN_RE.finditer(self.code):
            before = self.code[max(0, match.start() - 8):match.start()]
            if re.search(r"(?:const|let|var)\s*$", before):
                continue
            end = self._statement_end(match.end())
            assignments.append(([match.group(1)], self.code[match.end():end], self._line(match.start()), match.start()))
        assignments.sort(key=lambda item: item[3])
        for _ in range(3):  # fixed point over chained assignments
            changed = False
            for names, rhs, line, offset in assignments:
                if SANITIZER_RE.match(rhs):
                    continue
                origin = self._refs_taint(rhs, offset)
                if not origin:
                    continue
                scope = self._scope_of(offset)
                for name in names:
                    if any(o.scope == scope for o in self.tainted.get(name, [])):
                        continue
                    first_line = origin.line if origin.line > 0 else line
                    steps = (origin.steps or [(first_line, f"source: {origin.label}")]) + [(line, f"{name} = ...")]
                    self.tainted.setdefault(name, []).append(
                        Origin(origin.label, first_line, origin.server, steps[-8:], scope))
                    changed = True
            if not changed:
                break

    # ------------------------------------------------------------------ sinks
    def analyze(self) -> list[Decision]:
        self._collect_taint()
        decisions: list[Decision] = []
        for rule_id, regex, mode, server_only in SINKS:
            for match in regex.finditer(self.code):
                if rule_id == "SR-JS-007" and not self.uses_child_process:
                    continue
                line = self._line(match.start())
                if mode == "rhs":
                    end = self._statement_end(match.end())
                    candidates = [self.code[match.end():end]]
                elif mode == "html":
                    end = self.code.find("}}", match.end())
                    candidates = [self.code[match.end():end if end > 0 else match.end() + 200]]
                else:
                    args = self._call_args(match.end() - 1)
                    if mode == "arg0":
                        candidates = args[:1]
                    elif mode == "arg1":
                        candidates = args[1:2]
                    elif mode == "last":
                        candidates = args[-1:]
                    else:
                        candidates = args
                expression = " ".join(candidates)
                if rule_id == "SR-JS-009" and FUNCTION_ARG_RE.match(expression):
                    self.suppressed["callback instead of string"] = self.suppressed.get("callback instead of string", 0) + 1
                    decisions.append(Decision("constant", rule_id, line))
                    continue
                if not expression.strip() or CONSTANT_RE.match(expression):
                    self.suppressed["constant argument"] = self.suppressed.get("constant argument", 0) + 1
                    decisions.append(Decision("constant", rule_id, line))
                    continue
                if SANITIZER_RE.match(expression):
                    self.suppressed["sanitized argument"] = self.suppressed.get("sanitized argument", 0) + 1
                    decisions.append(Decision("constant", rule_id, line))
                    continue
                origin = self._refs_taint(expression, match.start())
                if origin and (origin.server or not server_only):
                    final_rule = "SR-JS-008" if rule_id == "SR-JS-007" else rule_id
                    first_line = origin.line if origin.line > 0 else line
                    steps = origin.steps or [(first_line, f"source: {origin.label}")]
                    flow = [{"line": ln, "label": label, "code": self._code_line(ln)} for ln, label in steps]
                    sink = re.sub(r"\s+", "", match.group(0)).rstrip("(=")
                    flow.append({"line": line, "label": f"sink: {sink}", "code": self._code_line(line)})
                    detail = f"Untrusted data from {origin.label} (line {first_line}) reaches {sink} (line {line})."
                    decisions.append(Decision("tainted", final_rule, line, TAINTED_SEVERITY.get(final_rule), flow, detail))
                    if final_rule != rule_id:
                        decisions.append(Decision("constant", rule_id, line))  # superseded by the tainted finding
                else:
                    decisions.append(Decision("dynamic", rule_id, line))
        return decisions


def analyze_js(original: str, code_view: str) -> tuple[list[Decision], dict[str, int]]:
    analyzer = JsFlowAnalyzer(original, code_view)
    return analyzer.analyze(), analyzer.suppressed
