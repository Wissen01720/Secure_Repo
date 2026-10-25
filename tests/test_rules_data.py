"""Rules live in data files and each one carries evidence that it works (C-08, C-41)."""
import os
import re

import pytest

from secure_repo.benchmark import examples
from secure_repo.core import redos
from secure_repo.core.rules import (RULE_ALIASES, RULE_DATA_DIR, RULES, RULES_BY_ID, RuleDataError, load_rules)

ONLINE = os.environ.get("SECURE_REPO_ONLINE_TESTS") == "1"


def test_every_rule_has_a_positive_and_a_negative_example():
    summary = examples.coverage()
    assert summary["missing"] == [], f"rules without both a positive and a negative example: {summary['missing']}"
    assert summary["with_examples"] == summary["rules"] == len(RULES)


def test_positive_examples_raise_their_rule_and_negative_examples_do_not():
    results = examples.run_examples()
    failures = [f"{r.rule_id} {r.kind}#{r.index}: {r.detail}" for r in results if not r.passed]
    assert not failures, "\n".join(failures)
    assert len(results) >= 300


@pytest.mark.skipif(not ONLINE, reason="needs OSV.dev / deps.dev (set SECURE_REPO_ONLINE_TESTS=1)")
def test_online_examples_for_the_dependency_database_rules():
    selected = [rule for rule in RULES if any(e.online for e in rule.examples)]
    assert {r.id for r in selected} >= {"SR-DEP-001", "SR-DEP-007", "SR-DEP-008", "SR-DEP-009"}
    failures = [f"{r.rule_id} {r.kind}: {r.detail}" for r in examples.run_examples(selected, online=True) if not r.passed]
    assert not failures, "\n".join(failures)


def test_example_placeholders_never_leave_a_token_shaped_literal_in_the_repository():
    for name in os.listdir(RULE_DATA_DIR):
        if name.endswith(".toml"):
            with open(os.path.join(RULE_DATA_DIR, name), encoding="utf-8") as handle:
                text = handle.read()
            assert not re.search(r"\bAKIA[0-9A-Z]{16}\b|\bghp_[A-Za-z0-9]{36}\b|\bsk_live_[0-9a-zA-Z]{24}\b|BEGIN (?:RSA )?PRIVATE KEY-----\n",
                                 text), name
    expanded = examples.expand("k = 'AKIA<<upper:16>>' t = '<<lit:abc>>' h = '<<hex:8>>'")
    assert re.search(r"AKIA[0-9A-Z]{16}", expanded) and "'abc'" in expanded and re.search(r"'[0-9a-f]{8}'", expanded)
    assert examples.expand("<<alnum:20>>") == examples.expand("<<alnum:20>>")      # deterministic
    with pytest.raises(ValueError):
        examples.expand("<<nope:3>>")


# ------------------------------------------------------------------------------------------ data invariants
def test_rule_data_is_well_formed():
    identifiers = [rule.id for rule in RULES]
    assert identifiers == sorted(identifiers) and len(set(identifiers)) == len(identifiers) == 193
    for rule in RULES:
        assert re.fullmatch(r"SR-[A-Z0-9]+-\d{3}", rule.id), rule.id
        assert rule.severity in ("critical", "high", "medium", "low", "info"), rule.id
        assert rule.confidence in ("low", "medium", "high"), rule.id
        assert not rule.cwe or re.fullmatch(r"CWE-\d+", rule.cwe), rule.id
        assert len(rule.description) > 40 and len(rule.recommendation) > 15, rule.id
        assert os.path.exists(os.path.join(RULE_DATA_DIR, rule.id.split("-")[1].lower() + ".toml")), rule.id
    assert all(new in RULES_BY_ID for new in RULE_ALIASES.values())


def test_no_built_in_pattern_can_backtrack_catastrophically():
    flagged = {rule.id: redos.check_pattern(rule.pattern) for rule in RULES if rule.pattern and redos.check_pattern(rule.pattern)}
    assert not flagged, flagged


def test_languages_groups_are_expanded():
    jwt = RULES_BY_ID["SR-GEN-011"]
    assert "Python" in jwt.languages and "Go" in jwt.languages and not any(name.startswith("@") for name in jwt.languages)
    assert RULES_BY_ID["SR-SEC-001"].languages == ("*",)


# ------------------------------------------------------------------------------------------ loader errors
def write_rule(directory, body, name="x.toml"):
    with open(os.path.join(directory, name), "w", encoding="utf-8") as handle:
        handle.write(body)


VALID = ("[[rule]]\nid = 'SR-X-001'\ntitle = 't'\nseverity = 'low'\ncategory = 'c'\ndescription = 'd'\nrecommendation = 'r'\n"
         "languages = ['@PY']\npattern = 'foo'\n")


def test_loader_reads_a_valid_file(tmp_path):
    write_rule(str(tmp_path), VALID)
    (rule,) = load_rules(str(tmp_path))
    assert rule.id == "SR-X-001" and rule.languages == ("Python",) and rule.regex.search("a foo b")


@pytest.mark.parametrize("body,message", [
    (VALID.replace("severity = 'low'", "severity = 'huge'"), "invalid severity"),
    (VALID.replace("title = 't'\n", ""), "missing 'title'"),
    (VALID + "surprise = 1\n", "unknown key"),
    (VALID.replace("'@PY'", "'@NOPE'"), "unknown language group"),
    (VALID.replace("pattern = 'foo'", "pattern = '(unclosed'"), "invalid pattern"),
    (VALID + "flags = ['BOGUS']\n", "unknown regex flag"),
    (VALID + "[[rule.example]]\nkind = 'maybe'\ncode = 'x'\n", "needs kind"),
    ("[[rule]\nid = 1", "not valid TOML"),
])
def test_loader_rejects_malformed_rule_files_naming_the_problem(tmp_path, body, message):
    write_rule(str(tmp_path), body)
    with pytest.raises(RuleDataError, match=message):
        load_rules(str(tmp_path))


def test_loader_rejects_duplicate_ids(tmp_path):
    write_rule(str(tmp_path), VALID, "a.toml")
    write_rule(str(tmp_path), VALID, "b.toml")
    with pytest.raises(RuleDataError, match="duplicate"):
        load_rules(str(tmp_path))


def test_packaged_data_files_are_declared_for_installation():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(root, "pyproject.toml"), encoding="utf-8") as handle:
        assert '"secure_repo.ruledata" = ["*.toml"]' in handle.read()
    assert os.path.exists(os.path.join(RULE_DATA_DIR, "__init__.py"))
