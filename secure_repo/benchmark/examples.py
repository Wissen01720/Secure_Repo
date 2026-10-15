"""Run the positive / negative examples that every rule carries in its data file.

A positive example must raise its rule, a negative one must not. This is the minimum evidence that a rule does
what its description says, and it is how the benchmark reports "rules with tests".
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import tempfile
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple

from secure_repo.core.events import EventBus
from secure_repo.core.rules import RULES, Rule, RuleExample
from secure_repo.core.scanner import Scanner, ScanOptions
from secure_repo.core.workspace import Target

# File name used when an example does not name one: the first language of the rule decides the extension.
DEFAULT_FILE = {
    "Python": "app.py", "JavaScript": "app.js", "TypeScript": "app.ts", "Vue": "App.vue", "Svelte": "App.svelte",
    "HTML": "index.html", "Java": "App.java", "Kotlin": "App.kt", "Scala": "App.scala", "Groovy": "App.groovy",
    "C#": "App.cs", "VB.NET": "App.vb", "F#": "App.fs", "PHP": "app.php", "Go": "main.go", "Ruby": "app.rb",
    "C": "main.c", "C++": "main.cpp", "Objective-C": "main.m", "Rust": "main.rs", "Swift": "main.swift",
    "Dart": "main.dart", "Lua": "main.lua", "Perl": "main.pl", "Elixir": "main.ex", "Solidity": "Token.sol",
    "Shell": "run.sh", "PowerShell": "run.ps1", "Batch": "run.bat", "Dockerfile": "Dockerfile", "YAML": "config.yml",
    "JSON": "config.json", "Terraform": "main.tf", "HCL": "main.hcl", "Properties": "app.properties",
    "INI": "app.ini", "Env": "app.env", "TOML": "config.toml", "Makefile": "Makefile", "Config": "app.conf",
}


_PLACEHOLDER = re.compile(r"<<(\w+):([^>]*)>>")
_ALPHABETS = {
    "upper": "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", "alnum": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
    "hex": "0123456789abcdef", "digits": "0123456789",
    "b64url": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_",
}


def expand(code: str) -> str:
    """Expand ``<<alnum:36>>`` (random-looking, deterministic characters) and ``<<lit:text>>`` (verbatim text).

    Examples for secret rules must not contain token-shaped literals: secret scanners, GitHub push protection and
    Secure Repo's own self-audit would all flag the data file. The runner builds the value at run time instead.
    """
    counter = [0]

    def replace(match: re.Match[str]) -> str:
        kind, argument = match.group(1), match.group(2)
        if kind == "lit":
            return argument
        if kind not in _ALPHABETS:
            raise ValueError(f"unknown example placeholder <<{kind}:...>>")
        counter[0] += 1
        alphabet, block = _ALPHABETS[kind], 0
        produced: List[str] = []
        while len(produced) < int(argument):
            digest = hashlib.sha256(f"{counter[0]}:{kind}:{argument}:{block}".encode()).digest()
            produced.extend(alphabet[b % len(alphabet)] for b in digest)
            block += 1
        return "".join(produced[:int(argument)])

    return _PLACEHOLDER.sub(replace, code)


@dataclass
class ExampleResult:
    rule_id: str
    kind: str
    index: int
    passed: bool
    detail: str = ""


def default_file(rule: Rule) -> str:
    for language in rule.languages:
        if language in DEFAULT_FILE:
            return DEFAULT_FILE[language]
    return "app.py"


def _safe_relative(name: str) -> str:
    parts = [p for p in name.replace("\\", "/").split("/") if p not in ("", ".", "..")]
    return "/".join(parts)


def _write(root: str, rel: str, content: str) -> None:
    path = os.path.join(root, *_safe_relative(rel).split("/"))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(content)


def _scan(root: str, online: bool = False) -> List[Dict]:
    options = ScanOptions(offline=not online, trust_repo_config=False, learning=False, resolve_versions=online,
                          enrich=online)
    report, _ = Scanner(options, EventBus()).run(Target.parse(root), write_reports=False)
    return report["findings"]


def _verdict(rule_id: str, example: RuleExample, findings: Iterable[Dict], prefix: str) -> Tuple[bool, str]:
    own = [f for f in findings if f["rule_id"] == rule_id and (prefix == "" or f["file"].startswith(prefix))]
    if example.kind == "positive":
        fired = [f for f in own if f["status"] == "open"]
        return (True, "") if fired else (False, "the rule did not fire" + (
            f" (status: {own[0]['status']}, confidence: {own[0]['confidence']})" if own else ""))
    return (True, "") if not own else (False, f"the rule fired at {own[0]['file']}:{own[0]['line']}: {own[0]['snippet'][:80]}")


def run_examples(rules: Optional[List[Rule]] = None, online: bool = False) -> List[ExampleResult]:
    """Scan every example (file-scope ones together, repository-scope ones each in their own folder).

    Examples that need the vulnerability databases (``online = true``) run only with ``online=True``.
    """
    rules = RULES if rules is None else rules
    results: List[ExampleResult] = []
    workdir = tempfile.mkdtemp(prefix="sr-examples-")
    try:
        batch_root = os.path.join(workdir, "batch")
        batch: List[Tuple[Rule, RuleExample, int, str]] = []
        for rule in rules:
            for index, example in enumerate(rule.examples):
                if example.scope == "repo" or example.online:
                    continue
                prefix = f"{rule.id}/{example.kind}-{index}/"
                _write(batch_root, prefix + (example.file or default_file(rule)), expand(example.code))
                for extra_name, extra_code in example.extra.items():
                    _write(batch_root, prefix + extra_name, expand(extra_code))
                batch.append((rule, example, index, prefix))
        if batch:
            findings = _scan(batch_root)
            for rule, example, index, prefix in batch:
                passed, detail = _verdict(rule.id, example, findings, prefix)
                results.append(ExampleResult(rule.id, example.kind, index, passed, detail))
        for rule in rules:
            for index, example in enumerate(rule.examples):
                if example.scope != "repo" and not example.online:
                    continue
                if example.online and not online:
                    continue
                root = os.path.join(workdir, f"{rule.id}-{example.kind}-{index}")
                _write(root, example.file or default_file(rule), expand(example.code))
                for extra_name, extra_code in example.extra.items():
                    _write(root, extra_name, expand(extra_code))
                passed, detail = _verdict(rule.id, example, _scan(root, online=example.online), "")
                results.append(ExampleResult(rule.id, example.kind, index, passed, detail))
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    return results


def coverage(rules: Optional[List[Rule]] = None) -> Dict[str, object]:
    """How many rules carry both a positive and a negative example."""
    rules = RULES if rules is None else rules
    both = [r.id for r in rules if any(e.kind == "positive" for e in r.examples)
            and any(e.kind == "negative" for e in r.examples)]
    missing = [r.id for r in rules if r.id not in set(both)]
    return {"rules": len(rules), "with_examples": len(both), "missing": missing}
