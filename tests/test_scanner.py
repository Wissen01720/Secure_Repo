import json
import os
import shutil

import pytest

from secure_repo.core.events import EventBus
from secure_repo.core.scanner import Scanner, ScanOptions
from secure_repo.core.workspace import Target
from tests.conftest import FAKE_AWS_KEY, FAKE_GH_TOKEN


def run(path, **kwargs):
    kwargs.setdefault("trust_repo_config", True)
    options = ScanOptions(offline=True, **kwargs)
    report, _ = Scanner(options, EventBus()).run(Target.parse(path), write_reports=False)
    return report


def rule_ids(report):
    return {f["rule_id"] for f in report["findings"]}


def test_detects_core_weaknesses(vulnerable_repo):
    report = run(vulnerable_repo)
    ids = rule_ids(report)
    expected = {
        "SR-SEC-001", "SR-SEC-003", "SR-SEC-019", "SR-SEC-020", "SR-PY-001", "SR-PY-002", "SR-PY-003",
        "SR-PY-004", "SR-PY-011", "SR-JS-002", "SR-JS-011", "SR-DOCKER-001", "SR-DOCKER-002", "SR-SH-001",
        "SR-DEP-002", "SR-DEP-004", "SR-DEP-005", "SR-DEP-006", "SR-HYG-001",
    }
    missing = expected - ids
    assert not missing, f"missing detections: {missing}"


def test_secrets_are_redacted_everywhere(vulnerable_repo):
    report = run(vulnerable_repo)
    dumped = json.dumps(report)
    assert FAKE_AWS_KEY not in dumped
    assert FAKE_GH_TOKEN not in dumped
    assert "Sup3rS3cretPassw0rd!" not in dumped


def test_nosec_comments_strings_and_docs_are_ignored(vulnerable_repo):
    report = run(vulnerable_repo)
    open_lines = [f["line"] for f in report["findings"] if f["rule_id"] == "SR-PY-001" and f["status"] == "open"]
    assert open_lines == [9]  # line 10 is a string literal, line 11 has "# nosec"
    inline = [f for f in report["findings"] if f["status"] == "suppressed_inline"]
    assert [f["line"] for f in inline] == [11] and inline[0]["triage"]["origin"] == "inline"  # kept in the audit trail
    assert not [f for f in report["findings"] if f["file"] == "docs/guide.md" and f["source"] == "code"]


def test_report_structure_and_score(vulnerable_repo):
    report = run(vulnerable_repo, compliance=True)
    assert report["schema"] == "secure-repo/report@1"
    assert 0 <= report["summary"]["score"] <= 100
    active = [f for f in report["findings"] if f["status"] not in ("false_positive", "filtered", "disabled_by_config",
                                                                   "suppressed_inline")]
    assert report["summary"]["findings"] == len(active)
    assert report["structure"]["files"] >= 7
    ids = [f["id"] for f in report["findings"]]
    assert len(ids) == len(set(ids))
    frameworks = {fw["id"] for fw in report["compliance"]["frameworks"]}
    assert {"owasp", "pci-dss", "iso27001", "soc2", "gdpr", "hipaa", "nist-ssdf"} <= frameworks


def test_dependency_inventory(vulnerable_repo):
    report = run(vulnerable_repo)
    names = {d["name"] for d in report["dependencies"]}
    assert {"flask", "requests", "lodash", "event-stream", "mylib"} <= names
    flask = next(d for d in report["dependencies"] if d["name"] == "flask")
    assert flask["version"] == "0.12.2" and flask["ecosystem"] == "PyPI"


def test_clean_repository_scores_well(tmp_path):
    root = tmp_path / "clean"
    (root / "src").mkdir(parents=True)
    (root / "src" / "util.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    for name in ("SECURITY.md", "LICENSE", "CODEOWNERS"):
        (root / name).write_text("x\n", encoding="utf-8")
    (root / ".gitignore").write_text(".env\n*.pem\n", encoding="utf-8")
    (root / ".github" / "workflows").mkdir(parents=True)
    (root / ".github" / "workflows" / "ci.yml").write_text("on: push\n", encoding="utf-8")
    report = run(str(root))
    assert report["summary"]["by_severity"]["critical"] == 0
    assert report["summary"]["by_severity"]["high"] == 0
    assert report["summary"]["grade"] in ("A", "B")


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_branch_export_does_not_touch_working_tree(git_repo):
    before = sorted(os.listdir(os.path.join(git_repo, "src")))
    report, _ = Scanner(ScanOptions(offline=True), EventBus()).run(Target.parse(git_repo, "feature"),
                                                                   write_reports=False)
    assert report["meta"]["mode"] == "branch-export"
    assert report["meta"]["branch"] == "feature"
    assert "SR-PY-002" in rule_ids(report)
    assert sorted(os.listdir(os.path.join(git_repo, "src"))) == before


def test_writes_organized_report_folder(vulnerable_repo, tmp_path):
    out = str(tmp_path / "reports")
    report, folder = Scanner(ScanOptions(offline=True, compliance=True, output_dir=out), EventBus()).run(
        Target.parse(vulnerable_repo))
    for rel in ("report.html", "report.json", "report.sarif", "summary.md", "findings/critical.md",
                "findings/findings.csv", "dependencies/inventory.csv", "dependencies/sbom.cdx.json",
                "structure/tree.txt", "compliance/compliance.json", "logs/scan.log", "MANIFEST.sha256", "README.txt"):
        assert os.path.isfile(os.path.join(folder, *rel.split("/"))), rel
    assert open(os.path.join(out, ".gitignore"), encoding="utf-8").read().strip().endswith("*")
    html = open(os.path.join(folder, "report.html"), encoding="utf-8").read()
    assert "window.__SR_REPORT__" in html and "<script src=" not in html
    assert FAKE_AWS_KEY not in html
    sarif = json.load(open(os.path.join(folder, "report.sarif"), encoding="utf-8"))
    assert sarif["version"] == "2.1.0" and sarif["runs"][0]["results"]
