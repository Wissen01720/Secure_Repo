"""Semantic analysis of Python code: AST checks + intra-procedural taint tracking.

Compared to regular expressions this engine understands the code:

* comments, docstrings and messages can never produce findings;
* imports and aliases are resolved (``import subprocess as sp; sp.call(...)``);
* arguments are inspected: constant commands / queries are not injectable, ``Loader=SafeLoader``,
  ``usedforsecurity=False`` and ``shell=False`` are honoured;
* untrusted data is followed from its source (``request.args``, ``input()``, route parameters,
  ``sys.argv``) through assignments, f-strings, concatenation and calls until it reaches a
  dangerous sink - the trace is reported as a data flow;
* sanitizers (``int()``, ``shlex.quote()``, ``html.escape()``, ``secure_filename()``...) stop the flow;
* non-cryptographic randomness is only reported when it produces security values.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set, Tuple

# Rules produced by this engine (their regular-expression versions are skipped for Python).
OWNED_RULES = {"SR-PY-001", "SR-PY-002", "SR-PY-003", "SR-PY-004", "SR-PY-005", "SR-PY-006", "SR-PY-008",
               "SR-PY-009", "SR-PY-010", "SR-PY-011", "SR-PY-012", "SR-PY-013", "SR-PY-015", "SR-PY-018",
               "SR-PY-019"}

REQUEST_ROOTS = {"request", "req"}
SOURCE_ATTRS = {"args", "form", "values", "json", "data", "cookies", "headers", "files", "GET", "POST",
                "COOKIES", "META", "FILES", "body", "query_params", "path_params", "query_string", "get_json",
                "get_data", "params", "stream", "view_args", "url", "path", "full_path"}
SANITIZERS = {
    "int", "float", "bool", "len", "abs", "round", "hash", "id", "isinstance", "ord", "type",
    "shlex.quote", "pipes.quote", "html.escape", "markupsafe.escape", "flask.escape", "cgi.escape",
    "escape", "bleach.clean", "werkzeug.utils.secure_filename", "secure_filename", "os.path.basename",
    "re.escape", "urllib.parse.quote", "urllib.parse.quote_plus", "quote", "quote_plus", "uuid.UUID",
    "django.utils.html.escape", "validators.url", "ipaddress.ip_address", "datetime.fromisoformat",
    "hashlib.sha256", "hashlib.sha512", "hmac.new", "json.dumps",
}
NON_PROPAGATING_METHODS = {"startswith", "endswith", "isdigit", "isalnum", "isalpha", "count", "index", "find",
                           "rfind", "__len__", "keys"}
CODE_EXEC = {"eval", "exec", "compile", "builtins.eval", "builtins.exec"}
OS_CMD = {"os.system", "os.popen", "os.popen2", "os.popen3", "os.spawnl", "os.spawnlp", "os.spawnv", "os.spawnvp",
          "os.execl", "os.execlp", "os.execv", "os.execvp", "commands.getoutput", "subprocess.getoutput",
          "subprocess.getstatusoutput"}
SUBPROCESS = {"subprocess.call", "subprocess.run", "subprocess.Popen", "subprocess.check_output",
              "subprocess.check_call"}
DESERIALIZE = {"pickle.loads", "pickle.load", "pickle.Unpickler", "cPickle.loads", "cPickle.load", "_pickle.loads",
               "dill.loads", "dill.load", "marshal.loads", "marshal.load", "shelve.open", "jsonpickle.decode",
               "pandas.read_pickle", "joblib.load"}
YAML_LOAD = {"yaml.load", "yaml.load_all", "yaml.unsafe_load", "yaml.unsafe_load_all", "yaml.full_load",
             "yaml.full_load_all"}
SAFE_LOADERS = {"SafeLoader", "CSafeLoader", "BaseLoader"}
RANDOM = {"random.random", "random.randint", "random.randrange", "random.choice", "random.choices",
          "random.getrandbits", "random.sample", "random.uniform"}
SQL_METHODS = {"execute", "executemany", "executescript", "raw", "extra", "mogrify"}
SQL_FUNCS = {"sqlalchemy.text", "sqlalchemy.sql.text", "sqlalchemy.sql.expression.text"}
PATH_SINKS = {"open": 0, "io.open": 0, "codecs.open": 0, "flask.send_file": 0, "send_file": 0,
              "flask.send_from_directory": 1, "send_from_directory": 1, "os.remove": 0, "os.unlink": 0,
              "shutil.rmtree": 0, "shutil.copy": 0, "shutil.copyfile": 0, "shutil.move": 0, "pathlib.Path": 0,
              "django.http.FileResponse": 0, "FileResponse": 0}
SSRF_SINKS = {"requests.get", "requests.post", "requests.put", "requests.patch", "requests.delete", "requests.head",
              "requests.request", "httpx.get", "httpx.post", "httpx.put", "httpx.delete", "httpx.request",
              "urllib.request.urlopen", "urllib.urlopen", "urllib2.urlopen", "urlopen"}
REDIRECTS = {"flask.redirect", "redirect", "django.shortcuts.redirect", "django.http.HttpResponseRedirect",
             "HttpResponseRedirect", "fastapi.responses.RedirectResponse", "starlette.responses.RedirectResponse",
             "RedirectResponse"}
TEMPLATE_SINKS = {"flask.render_template_string", "render_template_string", "jinja2.Template", "Template"}
MARKUP = {"markupsafe.Markup", "flask.Markup", "jinja2.Markup", "django.utils.safestring.mark_safe", "mark_safe",
          "Markup"}
ROUTE_DECORATORS = {"route", "get", "post", "put", "delete", "patch", "api_route", "websocket", "view"}
SECURITY_NAME = re.compile(r"(?i)(token|secret|passw|pwd|salt|nonce|otp|session|api_?key|secret_?key|private_?key|"
                           r"auth|csrf|reset|verif|captcha|credential|signature|iv\b|seed)")
SETTINGS_FILE = re.compile(r"(?i)(^|/)(settings|config|conf|production|prod)[\w.-]*\.py$")


@dataclass
class Taint:
    origin: str
    steps: List[Tuple[int, str]] = field(default_factory=list)

    def extend(self, line: int, label: str) -> Taint:
        steps = self.steps + [(line, label)]
        return Taint(self.origin, steps[-8:])


@dataclass
class PyFinding:
    rule_id: str
    line: int
    col: int
    severity: Optional[str] = None
    confidence: str = "high"
    detail: str = ""
    engine: str = "ast"
    flow: List[Dict] = field(default_factory=list)
    title: Optional[str] = None
    end_line: int = 0                                   # last line of the offending expression (multi-line calls)
    extra: Dict = field(default_factory=dict)           # signals for the confidence model


class _Scope:
    def __init__(self, tainted: Optional[Dict[str, Taint]] = None, route: bool = False, name: str = ""):
        self.tainted: Dict[str, Taint] = dict(tainted or {})
        self.dynamic: Set[str] = set()   # names holding dynamically built strings (SQL building)
        self.dynamic_src: Dict[str, List[ast.AST]] = {}   # ...and the expressions that built them
        self.route = route
        self.name = name


class PythonAnalyzer:
    def __init__(self, text: str, rel_path: str):
        self.text = text
        self.rel = rel_path
        self.lines = text.splitlines()
        self.aliases: Dict[str, str] = {}
        self.findings: List[PyFinding] = []
        self.suppressed: Dict[str, int] = {}
        self._seen: Set[Tuple[str, int]] = set()

    # ------------------------------------------------------------------ public
    def run(self) -> List[PyFinding]:
        tree = ast.parse(self.text)
        self._collect_imports(tree)
        module_scope = _Scope(name="<module>")
        self._block([s for s in tree.body if not isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef,
                                                                 ast.ClassDef))], module_scope)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._function(node)
            elif isinstance(node, ast.ClassDef):
                self._block([s for s in node.body if not isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef,
                                                                         ast.ClassDef))], _Scope(name=node.name))
        return self.findings

    # ------------------------------------------------------------------ helpers
    def _collect_imports(self, tree: ast.AST) -> None:
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.aliases[alias.asname or alias.name.split(".")[0]] = alias.name if alias.asname else alias.name.split(".")[0]
            elif isinstance(node, ast.ImportFrom) and node.module:
                for alias in node.names:
                    self.aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"

    def _qualname(self, node: ast.AST) -> str:
        parts: List[str] = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(self.aliases.get(node.id, node.id))
        elif isinstance(node, ast.Call):
            parts.append("?()")
        else:
            parts.append("?")
        return ".".join(reversed(parts))

    def _line_text(self, line: int) -> str:
        return self.lines[line - 1].strip() if 0 < line <= len(self.lines) else ""

    def _emit(self, rule_id: str, node: ast.AST, severity: Optional[str] = None, confidence: str = "high",
              detail: str = "", taint: Optional[Taint] = None, sink: str = "", title: Optional[str] = None,
              extra: Optional[Dict] = None) -> None:
        line = getattr(node, "lineno", 0)
        key = (rule_id, line)
        if key in self._seen:
            return
        self._seen.add(key)
        flow: List[Dict] = []
        engine = "ast"
        if taint is not None:
            engine = "taint"
            first = taint.steps[0][0] if taint.steps else line
            flow.append({"line": first, "label": f"source: {taint.origin}", "code": self._line_text(first)})
            for step_line, label in taint.steps[1:]:
                flow.append({"line": step_line, "label": label, "code": self._line_text(step_line)})
            flow.append({"line": line, "label": f"sink: {sink}", "code": self._line_text(line)})
            detail = (detail + " " if detail else "") + (
                f"Untrusted data from {taint.origin} (line {first}) reaches {sink} (line {line}).")
        self.findings.append(PyFinding(rule_id, line, getattr(node, "col_offset", 0), severity, confidence,
                                       detail.strip(), engine, flow, title,
                                       end_line=getattr(node, "end_lineno", None) or line, extra=extra or {}))

    def _skip(self, reason: str) -> None:
        self.suppressed[reason] = self.suppressed.get(reason, 0) + 1

    # ------------------------------------------------------------------ expressions
    def _is_source(self, node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Attribute):
            root = node.value
            if isinstance(root, ast.Name) and root.id in REQUEST_ROOTS and node.attr in SOURCE_ATTRS:
                return f"{root.id}.{node.attr}"
            if isinstance(root, ast.Attribute) and isinstance(root.value, ast.Name) and root.value.id == "self" \
                    and root.attr == "request" and node.attr in SOURCE_ATTRS:
                return f"self.request.{node.attr}"
            if self._qualname(node) == "sys.argv":
                return "sys.argv"
        if isinstance(node, ast.Call) and self._qualname(node.func) in ("input", "builtins.input", "raw_input"):
            return "input()"
        return None

    def taint(self, node: Optional[ast.AST], scope: _Scope) -> Optional[Taint]:
        if node is None:
            return None
        source = self._is_source(node)
        if source:
            return Taint(source, [(getattr(node, "lineno", 0), source)])
        if isinstance(node, ast.Name):
            return scope.tainted.get(node.id)
        if isinstance(node, (ast.Attribute, ast.Subscript, ast.Starred, ast.Await, ast.FormattedValue,
                             ast.NamedExpr)):
            return self.taint(node.value, scope)
        if isinstance(node, ast.Call):
            qualname = self._qualname(node.func)
            short = qualname.rsplit(".", 1)[-1]
            if qualname in SANITIZERS or short in {"secure_filename", "escape", "quote", "basename"}:
                return None
            if isinstance(node.func, ast.Attribute):
                if node.func.attr in NON_PROPAGATING_METHODS:
                    return None
                receiver = self.taint(node.func.value, scope)
                if receiver:
                    return receiver
            for arg in list(node.args) + [k.value for k in node.keywords]:
                found = self.taint(arg, scope)
                if found:
                    return found
            return None
        if isinstance(node, ast.BinOp):
            return self.taint(node.left, scope) or self.taint(node.right, scope)
        if isinstance(node, ast.JoinedStr):
            for value in node.values:
                found = self.taint(value, scope)
                if found:
                    return found
            return None
        if isinstance(node, ast.BoolOp):
            for value in node.values:
                found = self.taint(value, scope)
                if found:
                    return found
            return None
        if isinstance(node, ast.IfExp):
            return self.taint(node.body, scope) or self.taint(node.orelse, scope)
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            for element in node.elts:
                found = self.taint(element, scope)
                if found:
                    return found
            return None
        if isinstance(node, ast.Dict):
            for value in list(node.values) + [k for k in node.keys if k is not None]:
                found = self.taint(value, scope)
                if found:
                    return found
            return None
        if isinstance(node, (ast.ListComp, ast.GeneratorExp, ast.SetComp)):
            return self.taint(node.elt, scope) or next(
                (t for t in (self.taint(g.iter, scope) for g in node.generators) if t), None)
        return None

    @staticmethod
    def is_constant(node: Optional[ast.AST]) -> bool:
        if node is None:
            return True
        if isinstance(node, ast.Constant):
            return True
        if isinstance(node, ast.JoinedStr):
            return all(isinstance(v, ast.Constant) for v in node.values)
        if isinstance(node, ast.BinOp):
            return PythonAnalyzer.is_constant(node.left) and PythonAnalyzer.is_constant(node.right)
        if isinstance(node, (ast.List, ast.Tuple)):
            return all(PythonAnalyzer.is_constant(e) for e in node.elts)
        return False

    def is_dynamic_string(self, node: Optional[ast.AST], scope: _Scope) -> bool:
        if node is None:
            return False
        if isinstance(node, ast.JoinedStr):
            return any(isinstance(v, ast.FormattedValue) for v in node.values)
        if isinstance(node, ast.BinOp):
            if isinstance(node.op, ast.Mod) and isinstance(node.left, ast.Constant) and isinstance(node.left.value, str):
                return not self.is_constant(node.right)
            if isinstance(node.op, ast.Add):
                return (not self.is_constant(node)) and (
                    self._stringish(node.left) or self._stringish(node.right) or
                    self.is_dynamic_string(node.left, scope) or self.is_dynamic_string(node.right, scope))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            return isinstance(node.func.value, ast.Constant) and bool(node.args or node.keywords)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "join":
            return any(not self.is_constant(a) for a in node.args)
        if isinstance(node, ast.Name):
            return node.id in scope.dynamic
        return False

    # ---- what is interpolated into a dynamic string (evidence for SQL findings) ------------------------
    _QUOTERS = {"qn", "quote_name", "quote_ident", "quote_identifier", "escape_identifier", "identifier"}
    _NUMERIC = {"len", "int", "float", "range", "bool", "abs", "min", "max", "round", "sum", "enumerate"}

    def _leaves(self, node: ast.AST, scope: _Scope, depth: int = 0) -> List[ast.AST]:
        """The non-constant expressions that end up inside a dynamically built string."""
        if depth > 6 or isinstance(node, ast.Constant):
            return []
        if isinstance(node, ast.JoinedStr):
            return [leaf for value in node.values if isinstance(value, ast.FormattedValue)
                    for leaf in self._leaves(value.value, scope, depth + 1)]
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod) and self._stringish(node.left):
            right = node.right
            items = list(right.elts) if isinstance(right, (ast.Tuple, ast.List)) else (
                list(right.values) if isinstance(right, ast.Dict) else [right])
            return [leaf for item in items for leaf in self._leaves(item, scope, depth + 1)]
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return self._leaves(node.left, scope, depth + 1) + self._leaves(node.right, scope, depth + 1)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in ("format", "join") \
                and isinstance(node.func.value, (ast.Constant, ast.JoinedStr)):
            values = list(node.args) + [kw.value for kw in node.keywords]
            return [leaf for value in values for leaf in self._leaves(value, scope, depth + 1)]
        if isinstance(node, ast.Name) and node.id in scope.dynamic_src:
            return [leaf for source in scope.dynamic_src[node.id] for leaf in self._leaves(source, scope, depth + 1)]
        return [node]

    def _internal_fragment(self, node: ast.AST) -> bool:
        """True for values that cannot carry request data: own attributes, quoted identifiers, numbers, placeholders."""
        if isinstance(node, ast.Constant):
            return True
        if isinstance(node, ast.Attribute):
            root = node
            while isinstance(root, ast.Attribute):
                root = root.value
            return isinstance(root, ast.Name) and root.id in ("self", "cls")
        if isinstance(node, ast.Name):
            return node.id.isupper()
        if isinstance(node, ast.Subscript):
            return self._internal_fragment(node.value)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult):
            return self._internal_fragment(node.left) or self._internal_fragment(node.right)
        if isinstance(node, (ast.List, ast.Tuple)):
            return all(self._internal_fragment(element) for element in node.elts)
        if isinstance(node, ast.Call):
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else (func.id if isinstance(func, ast.Name) else "")
            lowered = name.lower()
            if lowered in self._QUOTERS or lowered.startswith("quote") or lowered in self._NUMERIC:
                return True
            if lowered in ("join", "strip", "lower", "upper", "str") and isinstance(func, ast.Attribute):
                return self._internal_fragment(func.value) and all(self._internal_fragment(a) for a in node.args)
        return False

    @staticmethod
    def _describe(node: ast.AST) -> str:
        try:
            text = ast.unparse(node)
        except Exception:  # pragma: no cover - unparse can fail on unusual trees
            text = type(node).__name__
        text = " ".join(text.split())
        return text if len(text) <= 48 else text[:45] + "..."

    @staticmethod
    def _stringish(node: ast.AST) -> bool:
        return (isinstance(node, ast.Constant) and isinstance(node.value, str)) or isinstance(node, ast.JoinedStr)

    @staticmethod
    def _kw(call: ast.Call, name: str) -> Optional[ast.AST]:
        for keyword in call.keywords:
            if keyword.arg == name:
                return keyword.value
        return None

    @staticmethod
    def _is_true(node: Optional[ast.AST]) -> bool:
        return isinstance(node, ast.Constant) and node.value is True

    @staticmethod
    def _is_false(node: Optional[ast.AST]) -> bool:
        return isinstance(node, ast.Constant) and node.value is False

    # ------------------------------------------------------------------ statements
    def _function(self, node: ast.AST) -> None:
        route = False
        for decorator in getattr(node, "decorator_list", []):
            target = decorator.func if isinstance(decorator, ast.Call) else decorator
            name = target.attr if isinstance(target, ast.Attribute) else getattr(target, "id", "")
            if name in ROUTE_DECORATORS:
                route = True
        tainted: Dict[str, Taint] = {}
        if route:
            args = node.args
            defaults = [None] * (len(args.args) - len(args.defaults)) + list(args.defaults)
            for arg, default in zip(args.args, defaults):
                if arg.arg in ("self", "cls", "request", "db", "session", "background_tasks", "response"):
                    continue
                if isinstance(default, ast.Call) and self._qualname(default.func).endswith("Depends"):
                    continue
                tainted[arg.arg] = Taint(f"route parameter '{arg.arg}'", [(node.lineno, f"route parameter '{arg.arg}'")])
        scope = _Scope(tainted, route=route, name=node.name)
        body = [s for s in node.body if not isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
        self._block(body, scope)

    def _block(self, statements: Sequence[ast.stmt], scope: _Scope) -> None:
        for statement in statements:
            self._statement(statement, scope)

    def _assign_names(self, target: ast.AST) -> List[str]:
        if isinstance(target, ast.Name):
            return [target.id]
        if isinstance(target, (ast.Tuple, ast.List)):
            names: List[str] = []
            for element in target.elts:
                names.extend(self._assign_names(element))
            return names
        if isinstance(target, ast.Starred):
            return self._assign_names(target.value)
        if isinstance(target, (ast.Attribute, ast.Subscript)):
            return [ast.unparse(target)] if hasattr(ast, "unparse") else []
        return []

    def _statement(self, stmt: ast.stmt, scope: _Scope) -> None:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return
        if isinstance(stmt, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            value = stmt.value
            targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
            names = [n for t in targets for n in self._assign_names(t)]
            self._scan_calls(value, scope, context=" ".join(names))
            self._settings_checks(stmt, names)
            if value is None:
                return
            found = self.taint(value, scope)
            dynamic = self.is_dynamic_string(value, scope)
            for name in names:
                if found:
                    scope.tainted[name] = found.extend(stmt.lineno, f"{name} = ...")
                elif not isinstance(stmt, ast.AugAssign):
                    scope.tainted.pop(name, None)
                if dynamic or (isinstance(stmt, ast.AugAssign) and name in scope.dynamic):
                    scope.dynamic.add(name)
                    sources = scope.dynamic_src.setdefault(name, []) if isinstance(stmt, ast.AugAssign) else []
                    sources.append(value)
                    scope.dynamic_src[name] = sources[-6:]
                elif not isinstance(stmt, ast.AugAssign):
                    scope.dynamic.discard(name)
                    scope.dynamic_src.pop(name, None)
            return
        if isinstance(stmt, ast.Return):
            self._scan_calls(stmt.value, scope, context=scope.name)
            if scope.route and stmt.value is not None:
                value = stmt.value
                # Only string-shaped responses: dicts/lists are serialized as JSON and objects are unknown types.
                stringish = isinstance(value, (ast.JoinedStr, ast.BinOp, ast.Subscript)) or (
                    isinstance(value, ast.Call) and isinstance(value.func, ast.Attribute) and value.func.attr == "format")
                found = self.taint(value, scope) if stringish else None
                if found:
                    self._emit("SR-PY-024", stmt, taint=found, sink="HTTP response body")
            return
        if isinstance(stmt, (ast.For, ast.AsyncFor)):
            self._scan_calls(stmt.iter, scope)
            found = self.taint(stmt.iter, scope)
            if found:
                for name in self._assign_names(stmt.target):
                    scope.tainted[name] = found.extend(stmt.lineno, f"for {name} in ...")
            self._block(stmt.body + stmt.orelse, scope)
            return
        if isinstance(stmt, (ast.With, ast.AsyncWith)):
            for item in stmt.items:
                self._scan_calls(item.context_expr, scope)
                if item.optional_vars is not None:
                    found = self.taint(item.context_expr, scope)
                    for name in self._assign_names(item.optional_vars):
                        if found:
                            scope.tainted[name] = found.extend(stmt.lineno, f"with ... as {name}")
            self._block(stmt.body, scope)
            return
        if isinstance(stmt, (ast.If, ast.While)):
            self._scan_calls(stmt.test, scope)
            self._block(stmt.body + stmt.orelse, scope)
            return
        if isinstance(stmt, ast.Try) or type(stmt).__name__ == "TryStar":
            self._block(stmt.body, scope)
            for handler in stmt.handlers:
                self._block(handler.body, scope)
            self._block(stmt.orelse + stmt.finalbody, scope)
            return
        if type(stmt).__name__ == "Match":
            self._scan_calls(stmt.subject, scope)
            for case in stmt.cases:
                self._block(case.body, scope)
            return
        for child in ast.iter_child_nodes(stmt):
            if isinstance(child, ast.expr):
                self._scan_calls(child, scope)

    def _settings_checks(self, stmt: ast.stmt, names: List[str]) -> None:
        value = getattr(stmt, "value", None)
        if "DEBUG" in names and self._is_true(value) and SETTINGS_FILE.search(self.rel):
            self._emit("SR-PY-010", stmt, confidence="medium",
                       detail="DEBUG is hardcoded to True in a settings module.")

    # ------------------------------------------------------------------ sinks
    def _scan_calls(self, node: Optional[ast.AST], scope: _Scope, context: str = "") -> None:
        if node is None:
            return
        for call in ast.walk(node):
            if isinstance(call, ast.Call):
                self._check_call(call, scope, context)
            elif isinstance(call, ast.keyword) and call.arg == "autoescape" and self._is_false(call.value):
                self._emit("SR-PY-013", call.value, detail="Template auto-escaping is explicitly disabled.")

    def _first_arg(self, call: ast.Call, index: int = 0, keyword: Optional[str] = None) -> Optional[ast.AST]:
        if len(call.args) > index:
            return call.args[index]
        return self._kw(call, keyword) if keyword else None

    def _check_call(self, call: ast.Call, scope: _Scope, context: str) -> None:
        qualname = self._qualname(call.func)
        short = qualname.rsplit(".", 1)[-1]
        attr = call.func.attr if isinstance(call.func, ast.Attribute) else ""

        # TLS verification disabled (any HTTP client call)
        if self._is_false(self._kw(call, "verify")) and not qualname.startswith(("jwt.", "jose.", "authlib.")):
            # jwt.decode(..., verify=False) skips the token *signature*, not TLS: that is SR-GEN-011.
            self._emit("SR-PY-006", call, detail="verify=False disables certificate validation for this request.")

        if qualname in CODE_EXEC:
            arg = self._first_arg(call)
            if self.is_constant(arg):
                return self._skip("constant argument")
            found = self.taint(arg, scope)
            if found:
                return self._emit("SR-PY-001", call, "critical", taint=found, sink=f"{short}()")
            return self._emit("SR-PY-001", call, confidence="medium",
                              detail=f"{short}() evaluates a non-constant expression.")

        if qualname in OS_CMD:
            arg = self._first_arg(call)
            if self.is_constant(arg):
                return self._skip("constant command")
            found = self.taint(arg, scope)
            if found:
                return self._emit("SR-PY-005", call, "critical", taint=found, sink=f"{qualname}()",
                                  title="OS command injection")
            return self._emit("SR-PY-005", call, confidence="medium",
                              detail=f"{qualname}() runs a shell command built at runtime.")

        if qualname in SUBPROCESS:
            shell = self._kw(call, "shell")
            arg = self._first_arg(call, keyword="args")
            found = self.taint(arg, scope)
            if self._is_true(shell):
                if found:
                    return self._emit("SR-PY-004", call, "critical", taint=found, sink=f"{qualname}(shell=True)",
                                      title="OS command injection")
                if self.is_constant(arg):
                    return self._emit("SR-PY-004", call, "low", confidence="medium",
                                      detail="shell=True with a constant command: not injectable today, but any "
                                             "future interpolation would be. Prefer an argument list.")
                return self._emit("SR-PY-004", call, confidence="medium",
                                  detail="shell=True with a command built at runtime.")
            if shell is not None and not self._is_false(shell) and not isinstance(shell, ast.Constant):
                return self._emit("SR-PY-004", call, "medium", confidence="low",
                                  detail="shell= is set from a variable; verify it can never be True with untrusted input.")
            return

        if qualname in DESERIALIZE:
            arg = self._first_arg(call)
            if self.is_constant(arg):
                return self._skip("constant argument")
            if isinstance(arg, ast.Call) and self._qualname(arg.func).rsplit(".", 1)[-1] in ("dumps", "dump"):
                return self._skip("round trip of data serialized in the same expression")
            found = self.taint(arg, scope)
            if found:
                return self._emit("SR-PY-002", call, "critical", taint=found, sink=f"{qualname}()")
            return self._emit("SR-PY-002", call, confidence="medium",
                              detail=f"{qualname}() deserializes data; make sure it never comes from an untrusted source.")

        if qualname in YAML_LOAD:
            loader = self._kw(call, "Loader") or (call.args[1] if len(call.args) > 1 else None)
            if qualname.startswith("yaml.load") and loader is not None:
                name = self._qualname(loader).rsplit(".", 1)[-1]
                if name in SAFE_LOADERS:
                    return self._skip("safe loader")
            found = self.taint(self._first_arg(call), scope)
            return self._emit("SR-PY-003", call, "critical" if found else None, taint=found,
                              sink=f"{qualname}()", detail="" if found else "No safe Loader is specified.")

        if qualname in ("hashlib.md5", "hashlib.sha1") or (qualname == "hashlib.new" and call.args and
                                                          isinstance(call.args[0], ast.Constant) and
                                                          str(call.args[0].value).lower() in ("md5", "sha1", "md4")):
            if self._is_false(self._kw(call, "usedforsecurity")):
                return self._skip("usedforsecurity=False")
            security = bool(SECURITY_NAME.search(context or "")) or bool(SECURITY_NAME.search(scope.name))
            return self._emit("SR-PY-008", call, None if security else "low", confidence="high" if security else "medium",
                              detail="" if security else "Weak hash used outside an obvious security context "
                                                         "(checksum/cache keys are acceptable; signatures and passwords are not).")

        if qualname in RANDOM:
            if SECURITY_NAME.search(context or "") or SECURITY_NAME.search(scope.name):
                return self._emit("SR-PY-009", call, "medium",
                                  detail=f"Predictable random value used for '{(context or scope.name)[:60]}'.")
            return self._skip("random outside security context")

        if attr == "run" and self._is_true(self._kw(call, "debug")):
            return self._emit("SR-PY-010", call, detail="The application server is started with debug=True.")

        if attr in SQL_METHODS or qualname in SQL_FUNCS or (short == "text" and qualname.startswith("sqlalchemy")):
            query = self._first_arg(call)
            if query is None or self.is_constant(query):
                return self._skip("parameterized/constant query")
            found = self.taint(query, scope)
            if found and (self.is_dynamic_string(query, scope) or isinstance(query, ast.Name)):
                return self._emit("SR-PY-011", call, "critical", taint=found, sink=f".{attr or short}()",
                                  title="SQL injection")
            if self.is_dynamic_string(query, scope):
                parts = self._leaves(query, scope)
                risky = [part for part in parts if not self._internal_fragment(part)]
                if risky or not parts:
                    names = ", ".join(f"`{self._describe(part)}`" for part in risky[:4])
                    detail = "The SQL text is assembled with string formatting instead of bound parameters"
                    if names:
                        detail += f"; {names} is interpolated into it."
                    elif isinstance(query, ast.Name):
                        detail = f"The SQL text in `{query.id}` is built with string formatting instead of bound parameters."
                    else:
                        detail += "."
                    return self._emit("SR-PY-011", call, confidence="medium", detail=detail)
                names = ", ".join(f"`{self._describe(part)}`" for part in parts[:4])
                return self._emit(
                    "SR-PY-011", call, confidence="low", extra={"internal_sql": True},
                    detail=f"The SQL text is built by formatting, but only internal identifiers ({names}) are "
                           f"interpolated and no request data reaches it. Bound parameters remain the safer habit "
                           f"for values.")
            return

        if qualname in ("tempfile.mktemp",):
            return self._emit("SR-PY-012", call)

        if qualname in MARKUP:
            arg = self._first_arg(call)
            if self.is_constant(arg):
                return self._skip("constant markup")
            found = self.taint(arg, scope)
            return self._emit("SR-PY-013", call, "high" if found else None, taint=found, sink=f"{short}()",
                              confidence="high" if found else "medium")

        if short in ("AutoAddPolicy", "WarningPolicy") and ("paramiko" in qualname or qualname == short):
            return self._emit("SR-PY-015", call)

        if qualname in PATH_SINKS:
            arg = self._first_arg(call, PATH_SINKS[qualname])
            found = self.taint(arg, scope)
            if found:
                return self._emit("SR-PY-018", call, taint=found, sink=f"{qualname}()", title="Path traversal")
            return

        if qualname in SSRF_SINKS:
            arg = self._first_arg(call, keyword="url")
            found = self.taint(arg, scope)
            if found:
                return self._emit("SR-PY-019", call, taint=found, sink=f"{qualname}()")
            return

        if qualname in REDIRECTS:
            found = self.taint(self._first_arg(call), scope)
            if found:
                return self._emit("SR-PY-023", call, taint=found, sink=f"{short}()")
            return

        if qualname in TEMPLATE_SINKS or attr == "from_string":
            arg = self._first_arg(call)
            if self.is_constant(arg):
                return
            found = self.taint(arg, scope)
            if found:
                return self._emit("SR-PY-022", call, "critical", taint=found, sink=f"{short}()")
            return


def analyze_python(text: str, rel_path: str) -> Tuple[List[PyFinding], Dict[str, int]]:
    """Run the analyzer. Raises SyntaxError when the file cannot be parsed (caller falls back to patterns)."""
    analyzer = PythonAnalyzer(text, rel_path)
    return analyzer.run(), analyzer.suppressed
