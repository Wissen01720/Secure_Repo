"""Engine precision (C-09 .. C-16): fewer false positives, new JavaScript rules, better evidence, stable rule IDs."""
import json
import os

import pytest

from secure_repo.core import triage
from secure_repo.core.events import EventBus
from secure_repo.core.rules import RULE_ALIASES, RULES_BY_ID, canonical_rule_id
from secure_repo.core.scanner import Scanner, ScanOptions
from secure_repo.core.workspace import Target
from tests.conftest import write


def scan(root, **options):
    options.setdefault("offline", True)
    options.setdefault("trust_repo_config", True)
    report, _ = Scanner(ScanOptions(**options), EventBus()).run(Target.parse(root), write_reports=False)
    return report


def hits(report, rule_id, file=None):
    return [f for f in report["findings"] if f["rule_id"] == rule_id and f["status"] == "open"
            and (file is None or f["file"] == file)]


# ---------------------------------------------------------------------- C-10  workflow script injection
SAFE_WORKFLOW = """name: pr
on: pull_request
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - name: safe, the value goes through the environment
        env:
          PR_BODY: ${{ github.event.pull_request.body }}
          TITLE: ${{ github.event.pull_request.title }}
        run: echo "$PR_BODY $TITLE"
      - uses: some/action@v1
        with:
          message: ${{ github.event.pull_request.title }}
      - name: after
        env:
          COMMENT: ${{ github.event.comment.body }}
        run: echo done
"""

UNSAFE_WORKFLOW = """name: pr
on: pull_request
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.pull_request.title }}"
      - name: block
        run: |
          echo start
          echo "${{ github.head_ref }}"
      - uses: actions/github-script@v7
        with:
          script: |
            core.info('${{ github.event.issue.body }}')
"""


def test_expressions_passed_through_env_or_with_are_not_script_injection(tmp_path):
    root = str(tmp_path / "r")
    write(root, ".github/workflows/safe.yml", SAFE_WORKFLOW)
    assert hits(scan(root), "SR-CI-002") == []


def test_expressions_inside_run_and_github_script_are_reported_at_the_right_line(tmp_path):
    root = str(tmp_path / "r")
    write(root, ".github/workflows/unsafe.yml", UNSAFE_WORKFLOW)
    assert sorted(f["line"] for f in hits(scan(root), "SR-CI-002")) == [7, 11, 15]


# ---------------------------------------------------------------------- C-09  new JavaScript rules
NODEGOAT_LIKE = """const session = require("express-session");
const swig = require("swig");
app.use(session({
    secret: "session_cookie_secret_key_here",
    saveUninitialized: true,
    resave: true,
    /*
    cookie: {
        httpOnly: true,
        // secure: true
    }
    */
}));
swig.setDefaults({ autoescape: false });
"""


def test_the_three_nodegoat_weaknesses_are_detected(tmp_path):
    root = str(tmp_path / "r")
    write(root, "server.js", NODEGOAT_LIKE)
    write(root, "config/env/all.js", 'module.exports = {\n  cookieSecret: "session_cookie_secret_key_here",\n};\n')
    report = scan(root)
    assert [f["line"] for f in hits(report, "SR-JS-025", "server.js")] == [14]
    assert hits(report, "SR-JS-026", "config/env/all.js") and hits(report, "SR-JS-026", "server.js")
    cookie = hits(report, "SR-JS-027", "server.js")
    assert cookie and "secure" in cookie[0]["detail"].lower() and cookie[0]["line"] == 3


@pytest.mark.parametrize("source", [
    'app.use(session({ secret: process.env.SESSION_SECRET, cookie: { secure: true, httpOnly: true } }));',
    "app.use(session({ secret: s, cookie: { secure: isProduction, httpOnly: true, sameSite: 'lax' } }));",
    'const cookieSecret = process.env.COOKIE_SECRET;',
    "nunjucks.configure('views', { autoescape: true });",
    "const transporter = nodemailer.createTransport({ host: h, port: 587, secure: false });",
])
def test_safe_session_and_template_configuration_is_not_reported(tmp_path, source):
    root = str(tmp_path / "r")
    write(root, "app.js", source + "\n")
    report = scan(root)
    for rule in ("SR-JS-025", "SR-JS-026", "SR-JS-027"):
        assert hits(report, rule) == [], (rule, source)


@pytest.mark.parametrize("source,rule", [
    ("app.use(session({ secret: s, cookie: { secure: false } }));", "SR-JS-027"),
    ("app.use(session({ secret: s, cookie: { secure: true, httpOnly: false } }));", "SR-JS-027"),
    ("app.use(session({ secret: s }));", "SR-JS-027"),
    ("res.cookie('sid', id, { httpOnly: false });", "SR-JS-027"),
    ("app.use(cookieSession({ keys: ['not-a-real-key-value'] }));", "SR-JS-026"),
    ("Handlebars.compile(tpl, { noEscape: true });", "SR-JS-025"),
])
def test_weak_cookie_and_template_settings_are_reported(tmp_path, source, rule):
    root = str(tmp_path / "r")
    write(root, "app.js", source + "\n")
    assert hits(scan(root), rule), source


# ---------------------------------------------------------------------- C-11 / C-16  SQL calibration and evidence
SQL_SOURCE = '''import sqlite3
from flask import request


class Backend:
    def introspect(self, cursor, table_name):
        cursor.execute("DESCRIBE %s" % self.connection.ops.quote_name(table_name))

    def create(self, schema_editor):
        schema_editor.execute(
            "CREATE TABLE %s (%s)"
            % (self.quote_name(self.name), self.sql_columns)
        )

    def unknown(self, cursor, table):
        sql = "SELECT * FROM %s WHERE x = 1" % table
        cursor.execute(
            sql
        )

    def tainted(self, cursor):
        cursor.execute("SELECT * FROM t WHERE id = " + request.args.get("id"))
'''


def sql_findings(tmp_path, name="app/db.py"):
    root = str(tmp_path / "r")
    write(root, name, SQL_SOURCE)
    return {f["line"]: f for f in hits(scan(root), "SR-PY-011")}


def test_internal_identifiers_are_low_confidence_and_unknown_values_never_high(tmp_path):
    found = sql_findings(tmp_path)
    assert found[7]["confidence"] == "low" and found[7]["extra"].get("internal_sql")
    assert found[10]["confidence"] == "low"
    assert found[17]["confidence"] == "medium"                      # no taint confirmed: capped at medium
    assert found[22]["confidence"] == "high" and found[22]["severity"] == "critical"   # taint confirmed


def test_sql_detail_names_the_interpolated_value_and_evidence_shows_the_whole_call(tmp_path):
    found = sql_findings(tmp_path)
    assert "`table`" in found[17]["detail"]
    assert "quote_name" in found[7]["detail"]
    evidence = found[10]["snippet"]
    assert "schema_editor.execute" in evidence and "self.sql_columns" in evidence and "\n" not in evidence
    assert found[10]["extra"]["fp_snippet"] == "schema_editor.execute("


def test_multiline_evidence_keeps_the_fingerprint_stable(tmp_path):
    finding = sql_findings(tmp_path)[10]
    legacy = dict(finding, snippet=finding["extra"]["fp_snippet"], extra={})
    assert triage.fingerprint(finding) == triage.fingerprint(legacy)


def test_findings_in_tests_are_one_level_lower_and_reported_apart(tmp_path):
    root = str(tmp_path / "r")
    write(root, "app/db.py", SQL_SOURCE)
    write(root, "tests/test_db.py", SQL_SOURCE)
    out = str(tmp_path / "out")
    scanner = Scanner(ScanOptions(offline=True, trust_repo_config=True, output_dir=out), EventBus())
    report, folder = scanner.run(Target.parse(root))
    production = [f for f in hits(report, "SR-PY-011") if not f["in_test"]]
    in_tests = [f for f in hits(report, "SR-PY-011") if f["in_test"]]
    assert {f["severity"] for f in production} == {"high", "critical"}
    lowered = [f for f in in_tests if f["extra"].get("test_downgrade")]
    assert lowered and all(f["severity"] != f["extra"]["original_severity"] for f in lowered)
    assert {f["extra"]["original_severity"] for f in lowered} <= {"high", "critical"}
    with open(os.path.join(folder, "findings", "high.md"), encoding="utf-8") as handle:
        assert "tests/test_db.py" not in handle.read()
    with open(os.path.join(folder, "findings", "tests.md"), encoding="utf-8") as handle:
        assert "tests/test_db.py" in handle.read()


# ---------------------------------------------------------------------- C-12 / C-13  third-party code and examples
LIBRARY = '/*!\n * Materialize v1.0.0 (http://materializecss.com)\n * Copyright 2014-2017 Materialize\n * MIT License\n */\n'


def test_a_bundled_library_is_reported_at_low_confidence_and_flagged(tmp_path):
    root = str(tmp_path / "r")
    write(root, "static/js/ui-kit.js", LIBRARY + "function go(c){ return eval(c); }\n")
    write(root, "static/js/jquery-3.6.0.js", "function go(c){ return eval(c); }\n")
    write(root, "static/js/own.js", "function go(c){ return eval(c); }\n")
    report = scan(root)
    kit, jq, own = (hits(report, "SR-JS-001", name) for name in ("static/js/ui-kit.js", "static/js/jquery-3.6.0.js",
                                                                   "static/js/own.js"))
    assert kit and jq and own
    assert kit[0]["confidence"] == "low" and "Materialize" in kit[0]["extra"]["third_party"]
    assert jq[0]["confidence"] == "low" and "jquery-3.6.0.js" in jq[0]["extra"]["third_party"]
    assert "third_party" not in own[0]["extra"] and own[0]["confidence"] != "low"


def test_findings_in_bundled_libraries_do_not_cap_the_grade(tmp_path):
    root = str(tmp_path / "r")
    write(root, "static/js/jquery-3.6.0.js", "function go(c){ return eval(c); }\n" * 3)
    summary = scan(root)["summary"]
    assert summary["grade_cap"] is None


def test_code_inside_pre_and_code_blocks_is_an_example_not_an_alert(tmp_path):
    root = str(tmp_path / "r")
    write(root, "views/help.html", "<h1>Help</h1>\n<pre><code>\nvar r = eval(userInput);\n</code></pre>\n"
                                     "<script>\nvar live = eval(location.hash);\n</script>\n")
    findings = {f["line"]: f for f in hits(scan(root), "SR-JS-001", "views/help.html")}
    assert findings[3]["extra"].get("example_block") and findings[3]["confidence"] == "low"
    assert not findings[6]["extra"].get("example_block") and findings[6]["confidence"] != "low"


# ---------------------------------------------------------------------- C-14  sensitive files
@pytest.mark.parametrize("name", ["Dockerfile.db", "Dockerfile.dev", "docker/Dockerfile.api.db", "Makefile.db",
                                  "Jenkinsfile.key", "Vagrantfile.bak", "Gemfile.lock.bak"])
def test_tool_files_with_a_variant_suffix_are_not_sensitive_files(tmp_path, name):
    root = str(tmp_path / "r")
    write(root, name, "FROM python:3.12-slim\n")
    assert hits(scan(root), "SR-SEC-020") == []


@pytest.mark.parametrize("name", ["data/users.db", "backup.sql", "dump.bak", ".env", "keys/server.key"])
def test_real_sensitive_files_are_still_reported(tmp_path, name):
    root = str(tmp_path / "r")
    key_header = "-----BEGIN " + "PRIVATE KEY-----"      # assembled so this repository holds no key-shaped literal
    write(root, name, key_header + "\nabc\n" if name.endswith(".key") else "SECRET=1\n")
    assert hits(scan(root), "SR-SEC-020"), name


# ---------------------------------------------------------------------- C-15  coherent IDs and migration
def test_rule_ids_match_the_languages_they_apply_to():
    groups = {"PY": {"Python"}, "PHP": {"PHP", "INI"}, "GO": {"Go"}, "RB": {"Ruby"}, "RS": {"Rust"}}
    for rule in RULES_BY_ID.values():
        prefix = rule.id.split("-")[1]
        if prefix in groups:
            assert set(rule.languages) <= groups[prefix], rule.id
        if prefix == "JS":
            assert set(rule.languages) <= {"JavaScript", "TypeScript", "Vue", "Svelte", "HTML"}, rule.id
        if prefix == "JAVA":
            assert set(rule.languages) <= {"Java", "Kotlin", "Scala", "Groovy", "Properties", "YAML"}, rule.id


def test_old_ids_resolve_to_the_new_ones():
    assert RULE_ALIASES["SR-JS-021"] == "SR-GEN-011" and RULES_BY_ID["SR-GEN-011"].title.startswith("JWT")
    assert canonical_rule_id(" SR-JS-021 ") == "SR-GEN-011" and canonical_rule_id("SR-PY-001") == "SR-PY-001"
    assert all(new in RULES_BY_ID and old not in RULES_BY_ID for old, new in RULE_ALIASES.items())


JWT_SOURCE = "import jwt\n\ndef read(token):\n    return jwt.decode(token, verify=False){}\n"


def test_the_jwt_rule_fires_on_python_with_a_python_agnostic_id(tmp_path):
    root = str(tmp_path / "r")
    write(root, "auth.py", JWT_SOURCE.format(""))
    assert hits(scan(root), "SR-GEN-011")


def test_old_ids_still_work_in_config_and_inline_comments(tmp_path):
    root = str(tmp_path / "disabled")
    write(root, "auth.py", JWT_SOURCE.format(""))
    write(root, ".securerepo.toml", '[rules]\ndisable = ["SR-JS-021"]\n')
    report = scan(root)
    assert hits(report, "SR-GEN-011") == []
    assert any(f["rule_id"] == "SR-GEN-011" and f["status"] == "disabled_by_config" for f in report["findings"])
    inline = str(tmp_path / "inline")
    write(inline, "auth.py", JWT_SOURCE.format("  # nosec SR-JS-021 reviewed"))
    assert hits(scan(inline), "SR-GEN-011") == []


def test_triage_history_survives_the_rename(tmp_path):
    root = str(tmp_path / "r")
    write(root, "auth.py", JWT_SOURCE.format(""))
    finding = hits(scan(root), "SR-GEN-011")[0]
    legacy_fingerprint = triage.fingerprint(dict(finding, rule_id="SR-JS-021"))
    assert triage.fingerprint(finding) == legacy_fingerprint          # hashed with the legacy id: old decisions match

    knowledge_path = str(tmp_path / "knowledge.json")
    with open(knowledge_path, "w", encoding="utf-8") as handle:
        json.dump({"version": 1, "patterns": [{"id": "p1", "rule_id": "SR-JS-021", "shape": "x"}],
                   "rule_stats": {"SR-JS-021": {"false_positive": 2}, "SR-GEN-011": {"false_positive": 1}},
                   "projects": {"k": {"name": "n", "decisions": {legacy_fingerprint: {"status": "false_positive",
                                                                                      "rule_id": "SR-JS-021"}}}}}, handle)
    knowledge = triage.KnowledgeBase(knowledge_path)
    assert knowledge.data["patterns"][0]["rule_id"] == "SR-GEN-011"
    assert knowledge.data["rule_stats"] == {"SR-GEN-011": {"false_positive": 3}}
    decision = knowledge.data["projects"]["k"]["decisions"][legacy_fingerprint]
    assert decision["rule_id"] == "SR-GEN-011"
