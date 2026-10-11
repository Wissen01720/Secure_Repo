"""Regression tests for review items C-05, C-06, C-07, C-19, C-22, C-25, C-26 and C-29."""
import csv
import io
import json
import os
import threading
import time
import urllib.error
import urllib.request

import pytest

from secure_repo.core import redos, updater
from secure_repo.core.config import load_config
from secure_repo.core.events import EventBus
from secure_repo.core.scanner import Scanner, ScanOptions
from secure_repo.core.scoring import compute_score
from secure_repo.core.workspace import Target
from secure_repo.gui.server import AppState, QuietServer, make_handler
from secure_repo.report.formats import csv_safe
from tests.conftest import write

BASE = ("import os\nfrom flask import request\n\n"
        "def run():\n    os.system(request.args.get('c'))\n    eval(request.args.get('x'))\n")


def scan(root, **options):
    options.setdefault("offline", True)
    options.setdefault("trust_repo_config", True)
    scanner = Scanner(ScanOptions(**options), EventBus())
    report, _ = scanner.run(Target.parse(root), write_reports=False)
    return report


def open_rules(report, file=None):
    return {f["rule_id"] for f in report["findings"] if f["status"] == "open" and (file is None or f["file"] == file)}


# ---------------------------------------------------------------------- C-05
def test_one_line_python_file_is_never_treated_as_minified(tmp_path):
    root = str(tmp_path / "r")
    padding = "x" * 21000
    write(root, "evil.py", f"import os; from flask import request; padding = '{padding}'; os.system(request.args.get('c'))\n")
    report = scan(root)
    assert "SR-PY-005" in open_rules(report, "evil.py")
    assert report["analysis"]["not_analyzed"]["minified"] == []


def test_minified_javascript_is_analyzed_in_reduced_mode_and_listed(tmp_path):
    root = str(tmp_path / "r")
    key = "AKIA" + "Z7Q2" + "LMNP" + "4RST" + "UVWX"
    bundle = ("var a=1;" * 4000) + f'eval(location.hash);var k="{key}";' + ("var b=2;" * 2000)
    write(root, "static/app.bundle.js", bundle + "\n")
    report = scan(root)
    assert report["analysis"]["not_analyzed"]["minified"] == ["static/app.bundle.js"]
    found = [f for f in report["findings"] if f["file"] == "static/app.bundle.js" and f["status"] == "open"]
    assert any(f["rule_id"] == "SR-SEC-001" for f in found)           # secrets are still detected
    assert all(f["confidence"] == "low" and f["extra"].get("minified") for f in found)
    assert not any(f["severity"] in ("medium", "low", "info") for f in found)  # reduced mode: secrets + critical only


# ---------------------------------------------------------------------- C-06
def test_source_folders_named_like_build_output_are_analyzed(tmp_path):
    root = str(tmp_path / "r")
    write(root, "app/build/handler.py", BASE)
    write(root, "src/vendor/util.py", BASE)
    write(root, "tools/target/run.py", BASE)
    report = scan(root)
    for path in ("app/build/handler.py", "src/vendor/util.py", "tools/target/run.py"):
        assert "SR-PY-005" in open_rules(report, path), path
    assert report["analysis"]["not_analyzed"]["directories"] == []


def test_generated_folders_are_skipped_only_with_evidence_and_listed(tmp_path):
    root = str(tmp_path / "r")
    write(root, "src/app.py", BASE)
    write(root, "vendor/lib.py", BASE)                      # vendor/ at the repository root
    write(root, "out/dist/bundle.py", BASE)                 # listed in .gitignore
    write(root, ".gitignore", "dist/\n")
    write(root, "svc/target/classes/A.class", "binary-ish")  # contains build artifacts
    write(root, "svc/target/README.py", BASE)
    write(root, "node_modules/x/index.js", "eval(location.hash)")
    report = scan(root)
    skipped = {d["path"]: d for d in report["analysis"]["not_analyzed"]["directories"]}
    assert set(skipped) == {"vendor", "out/dist", "svc/target", "node_modules"}
    assert skipped["vendor"]["reason"].startswith("vendor/ at the repository root")
    assert skipped["out/dist"]["reason"] == "listed in .gitignore"
    assert skipped["svc/target"]["reason"] == "contains build artifacts" and skipped["svc/target"]["files"] == 2
    assert skipped["node_modules"]["kind"] == "always"
    assert open_rules(report, "src/app.py")


def test_vendor_next_to_go_mod_is_third_party(tmp_path):
    root = str(tmp_path / "r")
    write(root, "services/api/go.mod", "module x\n")
    write(root, "services/api/vendor/dep.py", BASE)
    skipped = scan(root)["analysis"]["not_analyzed"]["directories"]
    assert [d["path"] for d in skipped] == ["services/api/vendor"]


# ---------------------------------------------------------------------- C-07
@pytest.mark.parametrize("pattern", [r"(a+)+$", r"(a|a)*", r"(.*)*", r"(\w+\s?)*", r"(a|ab)+c", r"([a-z]+)*x"])
def test_redos_prone_patterns_are_rejected(pattern):
    assert redos.check_pattern(pattern)


@pytest.mark.parametrize("pattern", [r"(?:[a-z0-9]+\.)+[a-z]+", r"[A-Z]{3}-\d+", r"\bnosec\b", r"(?:foo|bar)\d+",
                                      r"password\s*[:=]\s*['\"][^'\"]{4,}['\"]"])
def test_normal_patterns_are_accepted(pattern):
    assert redos.check_pattern(pattern) is None


def test_hostile_custom_rule_and_allowlist_cannot_hang_the_scan(tmp_path):
    root = str(tmp_path / "r")
    write(root, "a.py", "a" * 40 + "!\n")
    write(root, ".securerepo.toml", '[allowlist]\nvalues = ["(x+x+)+y"]\n[[custom_rules]]\nid = "EVIL-001"\n'
                                    'title = "x"\nseverity = "low"\npattern = "(a+)+$"\ncontext = "raw"\n')
    config = load_config(root)
    assert config.custom_rules == [] and config.allow_values == []
    assert any("EVIL-001" in e and "ReDoS" in e for e in config.errors)
    started = time.time()
    scanner = Scanner(ScanOptions(offline=True, trust_repo_config=True), EventBus())
    report, _ = scanner.run(Target.parse(root), write_reports=False)
    assert time.time() - started < 15
    assert report["analysis"]["custom_rules"] == []
    assert any("rejected" in line for line in scanner.log_lines)


# ---------------------------------------------------------------------- C-19
def finding(rule, severity, **extra):
    return dict({"rule_id": rule, "severity": severity}, **extra)


def test_open_critical_caps_the_grade_at_d_and_open_high_at_c():
    critical = compute_score([finding("A", "critical")])
    assert critical["grade"] == "D" and critical["score"] <= 59 and critical["uncapped_score"] > 59
    assert "1 open critical" in critical["cap"]["message"] and "uncapped" in critical["cap"]["message"]
    high = compute_score([finding("B", "high")])
    assert high["grade"] == "C" and high["score"] <= 74 and high["uncapped_score"] > 74
    assert compute_score([finding("C", "medium")])["cap"] is None
    assert compute_score([])["grade"] == "A"


def test_cap_ignores_suppressed_test_and_accepted_findings():
    for extra in ({"in_test": True}, {"status": "accepted_risk"}, {"status": "false_positive"},
                  {"status": "suppressed_inline"}):
        assert compute_score([finding("A", "critical", **extra)])["cap"] is None, extra


def test_scan_reports_the_cap(tmp_path):
    root = str(tmp_path / "r")
    write(root, "app.py", BASE)
    report = scan(root)
    assert report["summary"]["grade"] in ("D", "F") and report["summary"]["score"] <= 59
    assert report["summary"]["uncapped_score"] >= report["summary"]["score"]
    assert "grade_cap" in report["summary"]  # None when the raw penalty already puts the grade below the cap


# ---------------------------------------------------------------------- C-22
def test_csv_cells_cannot_be_formulas(tmp_path):
    assert csv_safe("=1+1") == "'=1+1" and csv_safe("@SUM(A1)") == "'@SUM(A1)" and csv_safe("-2+3") == "'-2+3"
    assert csv_safe("+cmd") == "'+cmd" and csv_safe("\t=x") == "'\t=x" and csv_safe("normal") == "normal"
    assert csv_safe(42) == 42
    root = str(tmp_path / "r")
    write(root, "=1+1.py", BASE)
    write(root, "@SUM(A1).py", BASE)
    out = str(tmp_path / "reports")
    _report, folder = Scanner(ScanOptions(offline=True, trust_repo_config=True, output_dir=out), EventBus()).run(
        Target.parse(root))
    with open(os.path.join(folder, "findings", "findings.csv"), encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    files = {row["file"] for row in rows}
    assert "'=1+1.py" in files and "'@SUM(A1).py" in files
    assert not any(cell.startswith(("=", "+", "-", "@")) for row in rows for cell in row.values())


# ---------------------------------------------------------------------- C-29
def test_report_folders_sort_by_time_and_latest_points_to_the_newest(tmp_path):
    root = str(tmp_path / "r")
    write(root, "app.py", BASE)
    out = str(tmp_path / "reports")
    names = []
    for _ in range(3):
        _r, folder = Scanner(ScanOptions(offline=True, trust_repo_config=True, output_dir=out), EventBus()).run(
            Target.parse(root))
        names.append(os.path.basename(folder))
    assert names == sorted(names) and len(set(names)) == 3
    assert all(len(name.rsplit("_", 1)[-1].split("-")[-1].split(".")[0]) >= 3 for name in names)
    with open(os.path.join(out, "latest.txt"), encoding="utf-8") as handle:
        assert handle.read().strip() == names[-1]


# ---------------------------------------------------------------------- C-25 / C-26
@pytest.fixture()
def server(tmp_path):
    state = AppState(ScanOptions(output_dir=str(tmp_path / "reports"), offline=True), "unit-test-token")
    srv = QuietServer(("127.0.0.1", 0), make_handler(state))
    state.port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield state
    srv.shutdown()
    srv.server_close()


def call(state, path, headers=None):
    request = urllib.request.Request(f"http://127.0.0.1:{state.port}{path}", headers=headers or {})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def test_token_is_accepted_only_in_the_header(server):
    assert call(server, "/api/context", {"X-SR-Token": "unit-test-token"})[0] == 200
    assert call(server, "/api/context?token=unit-test-token")[0] == 401
    assert call(server, "/api/context?token=unit-test-token", {"X-SR-Token": "wrong"})[0] == 401


def test_internal_errors_do_not_leak_details(server, monkeypatch, capsys):
    def boom(*_args, **_kwargs):
        raise RuntimeError(r"C:\Users\secret-person\private\path")

    monkeypatch.setattr(updater, "check", boom)
    status, body = call(server, "/api/update?force=1", {"X-SR-Token": "unit-test-token"})
    assert status == 500
    assert b"secret-person" not in body and b"RuntimeError" not in body
    assert "secret-person" in capsys.readouterr().err  # the detail goes to the local terminal only
