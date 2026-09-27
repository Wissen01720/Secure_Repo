# securerepo:ignore-file - engine unit tests contain vulnerable-looking samples on purpose (never executed).
import json
import os

from secure_repo.core import benchmark, lexer, versions
from secure_repo.core.events import EventBus
from secure_repo.core.jsflow import analyze_js
from secure_repo.core.pyast import analyze_python
from secure_repo.core.scanner import Scanner, ScanOptions
from secure_repo.core.workspace import Target
from tests.conftest import write


def rules_of(findings):
    return {(f.rule_id, f.line) for f in findings}


def test_lexer_masks_comments_and_strings_preserving_offsets():
    text = 'x = 1  # eval(a)\n"""doc eval(b)\nmore"""\ny = f"{name}"\n'
    views = lexer.mask(text, "Python")
    assert len(views["code"]) == len(text) and views["code"].count("\n") == text.count("\n")
    assert "eval" not in views["code"]
    assert "eval(b)" in views["no_comments"] and "eval(a)" not in views["no_comments"]
    js = "const q = `a ${req.query.id} b`; // exec(x)\n"
    assert "req.query.id" in lexer.mask(js, "JavaScript")["code"]


def test_python_taint_follows_variables_and_route_parameters():
    code = (
        "import subprocess as sp\n"
        "from flask import request, Flask\n"
        "app = Flask(__name__)\n"
        "@app.route('/u/<name>')\n"
        "def view(name):\n"
        "    host = request.args.get('h')\n"
        "    cmd = 'ping ' + host\n"
        "    sp.call(cmd, shell=True)\n"
        "    cursor.execute(f\"SELECT * FROM t WHERE n = '{name}'\")\n"
        "    return 'ok'\n"
    )
    findings, _ = analyze_python(code, "app.py")
    by_rule = {f.rule_id: f for f in findings}
    assert by_rule["SR-PY-004"].engine == "taint" and by_rule["SR-PY-004"].severity == "critical"
    assert [step["line"] for step in by_rule["SR-PY-004"].flow] == [6, 6, 7, 8]
    assert by_rule["SR-PY-011"].engine == "taint"


def test_python_semantic_checks_remove_false_positives():
    code = (
        "import os, random, subprocess, yaml, hashlib\n"
        "def f(uid):\n"
        "    '''eval(x) and pickle.loads(y) are forbidden'''\n"
        "    os.system('clear')\n"
        "    subprocess.run(['ls'], check=True)\n"
        "    cursor.execute('SELECT * FROM t WHERE id = %s', (uid,))\n"
        "    data = yaml.load(open('c'), Loader=yaml.SafeLoader)\n"
        "    delay = random.random()\n"
        "    digest = hashlib.md5(b'x', usedforsecurity=False)\n"
        "    return eval('1 + 1')\n"
    )
    findings, suppressed = analyze_python(code, "safe.py")
    assert findings == []
    assert sum(suppressed.values()) >= 5


def test_python_random_only_in_security_context():
    code = "import random\nsession_token = random.getrandbits(64)\njitter = random.random()\n"
    findings, _ = analyze_python(code, "x.py")
    assert rules_of(findings) == {("SR-PY-009", 2)}


def test_js_flow_confirms_discards_and_escalates():
    code = (
        "const cp = require('child_process');\n"
        "app.get('/x', (req, res) => {\n"
        "  const host = req.query.host;\n"
        "  cp.exec('ping ' + host);\n"
        "  cp.exec('git status');\n"
        "  const m = /a/.exec(host);\n"
        "});\n"
        "el.innerHTML = '';\n"
        "out.innerHTML = location.hash;\n"
    )
    decisions, _ = analyze_js(code, lexer.mask(code, "JavaScript")["code"])
    kinds = {(d.rule_id, d.line): d.kind for d in decisions}
    assert kinds[("SR-JS-008", 4)] == "tainted"
    assert kinds[("SR-JS-007", 5)] == "constant"
    assert ("SR-JS-007", 6) not in kinds and ("SR-JS-008", 6) not in kinds
    assert kinds[("SR-JS-002", 8)] == "constant"
    assert kinds[("SR-JS-002", 9)] == "tainted"


def test_version_ranges_per_ecosystem():
    npm = ["4.16.0", "4.17.21", "4.18.0-beta.1", "5.0.0"]
    assert versions.resolve("^4.16.0", npm, "npm") == ("4.17.21", "4.16.0")
    assert versions.resolve(">=2.0,<3", ["1.9", "2.1", "2.31.0", "3.0"], "PyPI") == ("2.31.0", "2.1")
    assert versions.resolve("~> 7.0.4", ["7.0.3", "7.0.8", "7.1.0"], "RubyGems") == ("7.0.8", "7.0.8")
    assert versions.resolve("[1.0,2.0)", ["0.9", "1.5", "2.0"], "Maven") == ("1.5", "1.5")
    assert versions.resolve("6.0.0", ["5.0.0", "6.0.0", "6.0.2"], "NuGet") == ("6.0.0", "6.0.0")
    assert versions.resolve("1.0", ["1.0.0", "1.4.2", "2.0.0"], "crates.io") == ("1.4.2", "1.0.0")


def test_versions_resolved_from_installed_environment_offline(tmp_path):
    root = str(tmp_path / "envrepo")
    write(root, "package.json", '{"dependencies": {"lodash": "^4.17.0"}}')
    write(root, "node_modules/lodash/package.json", '{"name": "lodash", "version": "4.17.15"}')
    write(root, "requirements.txt", "requests>=2.0\n")
    os.makedirs(os.path.join(root, ".venv", "Lib", "site-packages", "requests-2.19.1.dist-info"))
    report, _ = Scanner(ScanOptions(offline=True), EventBus()).run(Target.parse(root), write_reports=False)
    deps = {d["name"]: d for d in report["dependencies"]}
    assert deps["lodash"]["version"] == "4.17.15" and deps["lodash"]["resolved_by"] == "environment"
    assert deps["requests"]["version"] == "2.19.1" and deps["requests"]["resolved_by"] == "environment"
    guide = report["lockfile"]["manifests"]
    assert {entry["ecosystem"] for entry in guide} == {"npm", "PyPI"}


def test_benchmark_is_a_regression_gate():
    layered = benchmark.run()
    legacy = benchmark.run(semantic=False)
    assert layered["fp"] == 0 and layered["fn"] == 0
    assert legacy["precision"] < layered["precision"]


def test_reports_include_quality_and_lockfile_artifacts(vulnerable_repo, tmp_path):
    out = str(tmp_path / "reports")
    report, folder = Scanner(ScanOptions(offline=True, output_dir=out), EventBus()).run(Target.parse(vulnerable_repo))
    for rel in ("quality.md", "findings/suppressed.md", "dependencies/virtual-lock.json", "dependencies/lockfile-guide.md"):
        assert os.path.isfile(os.path.join(folder, *rel.split("/"))), rel
    assert report["analysis"]["engines"]["python_ast"] >= 1
    sarif = json.load(open(os.path.join(folder, "report.sarif"), encoding="utf-8"))
    assert any("codeFlows" in result for result in sarif["runs"][0]["results"])
