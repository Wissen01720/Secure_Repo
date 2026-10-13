"""Report location and the report's own Content-Security-Policy (C-24, C-27)."""
import os
import re

from secure_repo.core import triage
from secure_repo.core.events import EventBus
from secure_repo.core.scanner import Scanner, ScanOptions
from secure_repo.core.workspace import Target
from secure_repo.report import html as report_html
from secure_repo.report.writer import ensure_output_root
from tests.conftest import write


def scan_report(tmp_path):
    root = str(tmp_path / "r")
    write(root, "app.py", "x = 1\n")
    report, _ = Scanner(ScanOptions(offline=True, trust_repo_config=True), EventBus()).run(
        Target.parse(root), write_reports=False)
    return report


def test_csp_allows_scripts_only_by_hash(tmp_path):
    page = report_html.build_html_report(scan_report(tmp_path))
    policy = re.search(r'Content-Security-Policy" content="([^"]+)"', page).group(1)
    script_src = re.search(r"script-src ([^;]+);", policy).group(1)
    assert "'unsafe-inline'" not in script_src and "'unsafe-eval'" not in script_src
    scripts = re.findall(r"<script>(.*?)</script>", page, re.DOTALL)
    assert len(scripts) >= 4
    hashes = re.findall(r"'sha256-[A-Za-z0-9+/=]+'", script_src)
    assert len(hashes) == len(set(hashes)) == len(scripts)
    assert "default-src 'none'" in policy and "connect-src 'none'" in policy and "base-uri 'none'" in policy


def test_every_inline_script_matches_a_hash_and_nothing_else_does():
    page = "<script>alert(1)</script><script>var a=1</script>"
    listed = report_html.script_hashes(page)
    assert listed.count("sha256-") == 2
    assert report_html.script_hashes(page + "<script>evil()</script>") != listed
    assert report_html.script_hashes("<p>no scripts</p>") == "'none'"


def test_embedded_data_cannot_close_the_script_block(tmp_path):
    report = scan_report(tmp_path)
    report["meta"]["name"] = "</script><script>alert(1)</script>"
    page = report_html.build_html_report(report)
    assert page.count("</script>") == page.count("<script>")
    assert "<script>alert(1)" not in page


def test_default_reports_live_outside_the_audited_repository(tmp_path, isolated_knowledge):
    default = ScanOptions().output_dir
    assert default == triage.default_output_dir()
    assert os.path.commonpath([default, isolated_knowledge]) == isolated_knowledge
    assert os.path.basename(default) == "reports"


def test_reports_inside_a_git_repository_are_also_excluded_from_git(tmp_path):
    repo = tmp_path / "project"
    (repo / ".git" / "info").mkdir(parents=True)
    ensure_output_root(str(repo / "out" / "reports"))
    exclude = (repo / ".git" / "info" / "exclude").read_text(encoding="utf-8")
    assert "/out/reports/" in exclude.splitlines()
    ensure_output_root(str(repo / "out" / "reports"))                       # idempotent
    assert (repo / ".git" / "info" / "exclude").read_text(encoding="utf-8").count("/out/reports/") == 1
    assert (repo / "out" / "reports" / ".gitignore").exists()


def test_reports_outside_any_repository_touch_no_git_files(tmp_path):
    ensure_output_root(str(tmp_path / "plain" / "reports"))
    assert not (tmp_path / "plain" / ".git").exists()
