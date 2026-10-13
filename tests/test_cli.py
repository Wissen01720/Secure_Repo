"""Command-line interface: exit codes, sub-commands and renderers, driven through main() (C-38)."""
import json
import os
import re

import pytest

from secure_repo import __version__
from secure_repo.cli import main as cli
from secure_repo.cli import updates, views
from secure_repo.core import updater
from secure_repo.core.events import EventBus
from secure_repo.core.scanner import Scanner, ScanOptions
from secure_repo.core.workspace import Target
from tests.conftest import write

ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


@pytest.fixture(autouse=True)
def wide_console(monkeypatch):
    """Tables fold or truncate at the terminal width; tests must not depend on the width of the machine running them."""
    from secure_repo.cli.theme import console

    monkeypatch.setattr(console, "_width", 200, raising=False)


def run(argv, capsys):
    code = cli.main(["--no-update-check"] + argv)
    captured = capsys.readouterr()
    return code, ANSI.sub("", captured.out + captured.err)


@pytest.fixture()
def clean_repo(tmp_path):
    root = str(tmp_path / "clean")
    write(root, "app.py", "def add(a, b):\n    return a + b\n")
    return root


def scan_args(root, out, *extra):
    return ["scan", root, "--offline", "--yes", "--plain", "--no-menu", "-o", out, *extra]


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as stop:
        cli.main(["--version"])
    assert stop.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_scan_of_a_clean_repository_passes_the_gate(clean_repo, tmp_path, capsys):
    code, out = run(scan_args(clean_repo, str(tmp_path / "out"), "--fail-on", "high"), capsys)
    assert code == 0
    assert "latest.txt" in os.listdir(str(tmp_path / "out"))


def test_fail_on_turns_findings_into_exit_code_3(vulnerable_repo, tmp_path, capsys):
    code, out = run(scan_args(vulnerable_repo, str(tmp_path / "out"), "--fail-on", "high"), capsys)
    assert code == 3 and "exiting with code 3" in out
    code, _ = run(scan_args(vulnerable_repo, str(tmp_path / "out2")), capsys)
    assert code == 0                                           # without --fail-on the scan itself succeeds


def test_usage_errors_have_distinct_exit_codes(tmp_path, clean_repo, capsys):
    code, out = run(scan_args(str(tmp_path / "missing"), str(tmp_path / "o")), capsys)
    assert code == 1 and "not found" in out.lower()
    code, out = run(scan_args(clean_repo, str(tmp_path / "o"), "--compliance", "nonsense"), capsys)
    assert code == 2 and "Unknown framework" in out
    with pytest.raises(SystemExit) as stop:
        cli.main(["scan", "--min-confidence", "bogus"])
    assert stop.value.code == 2


def test_compliance_flag_writes_framework_reports(clean_repo, tmp_path, capsys):
    out_dir = str(tmp_path / "out")
    code, _ = run(scan_args(clean_repo, out_dir, "--compliance", "owasp"), capsys)
    assert code == 0
    folder = os.path.join(out_dir, open(os.path.join(out_dir, "latest.txt")).read().strip())
    assert os.path.exists(os.path.join(folder, "compliance", "owasp.md"))


def test_without_a_terminal_the_bare_command_prints_help(capsys):
    code, out = run([], capsys)
    assert code == 0 and "usage:" in out and "scan" in out


def test_rules_and_frameworks_listings(capsys):
    code, out = run(["rules", "--search", "sql"], capsys)
    assert code == 0 and "SQL" in out.upper()
    code, out = run(["frameworks"], capsys)
    assert code == 0 and "owasp" in out.lower() and "pci" in out.lower()


def test_init_config_creates_a_template_once(tmp_path, capsys):
    repo = str(tmp_path / "r")
    os.makedirs(repo)
    code, _ = run(["init-config", repo], capsys)
    assert code == 0 and os.path.exists(os.path.join(repo, ".securerepo.toml"))
    code, out = run(["init-config", repo], capsys)                 # never overwrites an existing file
    assert "exists" in out.lower() or code != 0


def test_benchmark_command_reports_precision(capsys):
    code, out = run(["benchmark"], capsys)
    assert code == 0 and "precision" in out.lower()


def test_triage_workflow_from_the_command_line(vulnerable_repo, tmp_path, capsys):
    out_dir = str(tmp_path / "out")
    run(scan_args(vulnerable_repo, out_dir), capsys)
    folder = os.path.join(out_dir, open(os.path.join(out_dir, "latest.txt")).read().strip())
    report = json.load(open(os.path.join(folder, "report.json"), encoding="utf-8"))
    target = next(f for f in report["findings"] if f["rule_id"].startswith("SR-PY") and f["status"] == "open")

    code, out = run(["triage", "mark", folder, target["id"], "--status", "false_positive", "--reason", "test data"], capsys)
    assert code == 0
    code, out = run(["triage", "list"], capsys)
    assert code == 0 and target["rule_id"] in out and "false_positive" in out
    code, out = run(["triage", "stats"], capsys)
    assert code == 0 and "knowledge base" in out
    exported = str(tmp_path / "knowledge.json")
    assert run(["triage", "export", exported], capsys)[0] == 0 and os.path.exists(exported)
    assert run(["triage", "reset", "--yes"], capsys)[0] == 0
    assert run(["triage", "import", exported], capsys)[0] == 0
    code, out = run(["triage", "list"], capsys)
    assert target["rule_id"] in out


def test_update_check_exit_codes(monkeypatch, capsys):
    base = dict(mode="git", checked_at=0.0, current_version=__version__)
    monkeypatch.setattr(updater, "check", lambda force=False: updater.UpdateInfo(error="offline", **base))
    assert run(["update", "--check"], capsys)[0] == 1
    monkeypatch.setattr(updater, "check", lambda force=False: updater.UpdateInfo(
        available=True, latest_version="9.9.9", latest_commit="abcdef1234567", **base))
    code, out = run(["update", "--check"], capsys)
    assert code == 10 and "9.9.9" in out
    monkeypatch.setattr(updater, "check", lambda force=False: updater.UpdateInfo(**base))
    assert run(["update", "--check"], capsys)[0] == 0


def test_update_banners_render(capsys):
    info = updater.UpdateInfo(mode="git", checked_at=0.0, current_version="1.0.0", available=True, latest_version="1.1.0",
                              latest_commit="abcdef1234567", changes=["Faster scans"])
    updates.render_available(info)
    updates.render_compact(info)
    updates.render_compact(None)
    updates.render_post_update({"from": "1.0.0", "to": "1.1.0", "changes": ["abc1234 Faster scans"]})
    out = ANSI.sub("", capsys.readouterr().out)
    assert "1.1.0" in out


def test_every_renderer_handles_a_real_report(vulnerable_repo, tmp_path, capsys):
    report, folder = Scanner(ScanOptions(offline=True, compliance=True, trust_repo_config=True,
                                         output_dir=str(tmp_path / "out")), EventBus()).run(Target.parse(vulnerable_repo))
    views.render_summary(report, folder)
    views.render_findings_table([f for f in report["findings"] if f["status"] == "open"], limit=5, title="TOP")
    views.render_finding_detail(report, next(f for f in report["findings"] if f["status"] == "open"), vulnerable_repo)
    views.render_dependencies(report)
    views.render_dependencies(report, only_vulnerable=True, limit=3)
    views.render_compliance(report)
    views.render_compliance(report, detailed=True)
    views.render_structure_boxes(report["structure"])
    views.render_structure_tree(report["structure"])
    views.render_output_tree(folder)
    views.render_quality(report)
    views.render_quality(report, detailed=True)
    views.render_lockfile(report)
    out = ANSI.sub("", capsys.readouterr().out)
    assert "Security score" in out or "SCORE" in out.upper()
    assert report["findings"][0]["rule_id"] in out or "SR-" in out
    # the console folds long paths at the terminal width, so compare without line breaks or spaces
    assert folder and os.path.basename(folder) in re.sub(r"\s+", "", out)


def test_summary_shows_the_grade_cap_and_blind_spots(tmp_path, capsys):
    root = str(tmp_path / "r")
    write(root, "app.py", "import os\nfrom flask import request\nos.system(request.args.get('c'))\n")
    write(root, "static/app.min.js", "var a=1;" * 5000 + "\n")
    report, folder = Scanner(ScanOptions(offline=True, trust_repo_config=True, output_dir=str(tmp_path / "out")),
                             EventBus()).run(Target.parse(root))
    views.render_summary(report, folder)
    views.render_quality(report)
    out = ANSI.sub("", capsys.readouterr().out)
    assert "Not analyzed" in out
