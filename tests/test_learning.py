import json
import os

import pytest

from secure_repo.core import review, triage
from secure_repo.core.config import load_config
from secure_repo.core.events import EventBus
from secure_repo.core.scanner import Scanner, ScanOptions
from secure_repo.core.workspace import Target
from tests.conftest import write


def scan(path, **options):
    options.setdefault("trust_repo_config", True)  # these temp folders are the "analyst's own" projects
    return Scanner(ScanOptions(offline=True, **options), EventBus()).run(Target.parse(path), write_reports=False)[0]


def by_rule(report, rule_id):
    return [f for f in report["findings"] if f["rule_id"] == rule_id]


def make_repo(root, extra_lines=0):
    write(root, "src/server.py", "\n" * extra_lines + "def main(app):\n    app.run(host='0.0.0.0', port=8080)\n")
    write(root, "src/other.py", "def run(app):\n    app.run(host='0.0.0.0', port=9090)\n")


def test_fingerprint_survives_line_shifts(tmp_path):
    root = str(tmp_path / "repo")
    make_repo(root)
    first = [f for f in by_rule(scan(root), "SR-GEN-006") if f["file"] == "src/server.py"][0]
    make_repo(root, extra_lines=5)
    second = [f for f in by_rule(scan(root), "SR-GEN-006") if f["file"] == first["file"]][0]
    assert first["line"] != second["line"] and first["fingerprint"] == second["fingerprint"]


def test_false_positive_decision_is_reapplied_and_excluded_from_score(tmp_path):
    root = str(tmp_path / "repo")
    make_repo(root)
    report = scan(root)
    target = [f for f in by_rule(report, "SR-GEN-006") if f["file"] == "src/server.py"][0]
    result = review.triage(report, [target["id"]], "false_positive", "Bound inside a container on purpose")
    assert report["summary"]["suppressed"] == 1 and result["changed"] == [target["id"]]
    rescanned = scan(root)
    statuses = {f["file"]: f["status"] for f in by_rule(rescanned, "SR-GEN-006")}
    assert statuses == {"src/server.py": "false_positive", "src/other.py": "open"}


def test_learned_pattern_suppresses_similar_code(tmp_path):
    root = str(tmp_path / "repo")
    make_repo(root)
    report = scan(root)
    target = [f for f in by_rule(report, "SR-GEN-006") if f["file"] == "src/server.py"][0]
    result = review.triage(report, [target["id"]], "false_positive", "Container networking", scope="project-pattern")
    assert result["learned"] == 1  # the same code shape in src/other.py was suppressed immediately
    rescanned = scan(root)
    assert all(f["status"] == "false_positive" for f in by_rule(rescanned, "SR-GEN-006"))
    origins = {f["triage"]["origin"] for f in by_rule(rescanned, "SR-GEN-006")}
    assert origins == {"decision", "learned-pattern"}


def test_noisy_rule_confidence_drops_after_feedback(tmp_path):
    root = str(tmp_path / "repo")
    for index in range(4):
        write(root, f"svc{index}.py", f"def s(app):\n    app.run(host='0.0.0.0', port={8000 + index})\n")
    report = scan(root)
    baseline = by_rule(report, "SR-GEN-006")[0]["confidence_score"]
    ids = [f["id"] for f in by_rule(report, "SR-GEN-006")[:3]]
    review.triage(report, ids, "false_positive", "Always intended in this code base")
    rescanned = scan(root)
    remaining = [f for f in by_rule(rescanned, "SR-GEN-006") if f["status"] == "open"]
    assert remaining and remaining[0]["confidence_score"] < baseline


def test_triage_requires_reason_for_false_positive(tmp_path):
    root = str(tmp_path / "repo")
    make_repo(root)
    report = scan(root)
    with pytest.raises(ValueError):
        review.triage(report, [report["findings"][0]["id"]], "false_positive", "")


def test_triage_refreshes_report_folder(tmp_path):
    root = str(tmp_path / "repo")
    make_repo(root)
    report, folder = Scanner(ScanOptions(offline=True, output_dir=str(tmp_path / "out")), EventBus()).run(Target.parse(root))
    target = by_rule(report, "SR-GEN-006")[0]
    review.triage(report, [target["id"]], "accepted_risk", "Documented in threat model", report_dir=folder)
    saved = json.load(open(os.path.join(folder, "report.json"), encoding="utf-8"))
    assert [f["status"] for f in saved["findings"] if f["id"] == target["id"]] == ["accepted_risk"]
    assert "[TRIAG]" in open(os.path.join(folder, "logs", "scan.log"), encoding="utf-8").read()


def test_project_config_custom_rules_allowlist_and_overrides(tmp_path):
    root = str(tmp_path / "repo")
    make_repo(root)
    write(root, "src/flags.py", "enable_debug_endpoint = True\n")
    write(root, ".securerepo.toml", "\n".join([
        "[rules]", 'disable = ["SR-HYG-004"]', "[rules.severity]", '"SR-HYG-001" = "info"',
        "[allowlist]", 'paths = ["src/other.py"]',
        "[[custom_rules]]", 'id = "ACME-001"', 'title = "Debug endpoint flag"', 'severity = "medium"',
        'pattern = "enable_debug_endpoint\\\\s*=\\\\s*True"', 'languages = ["Python"]', 'context = "code"',
    ]) + "\n")
    config = load_config(root)
    assert not config.errors and config.custom_rules[0].id == "ACME-001"
    report = scan(root)
    assert by_rule(report, "ACME-001") and by_rule(report, "ACME-001")[0]["engine"] == "custom"
    assert [f["status"] for f in by_rule(report, "SR-HYG-004")] == ["disabled_by_config"]  # kept, never deleted
    assert by_rule(report, "SR-HYG-001")[0]["severity"] == "info"
    other = [f for f in by_rule(report, "SR-GEN-006") if f["file"] == "src/other.py"][0]
    assert other["status"] == "false_positive" and other["triage"]["origin"] == "config"


def test_min_confidence_filters_but_keeps_audit_trail(tmp_path):
    root = str(tmp_path / "repo")
    make_repo(root)
    report = scan(root, min_confidence="high")
    filtered = [f for f in report["findings"] if f["status"] == "filtered"]
    assert filtered and report["summary"]["suppressed"] >= len(filtered)


def test_knowledge_export_import_and_cases(tmp_path):
    root = str(tmp_path / "repo")
    make_repo(root)
    report = scan(root)
    review.triage(report, [by_rule(report, "SR-GEN-006")[0]["id"]], "false_positive", "fp", scope="global-pattern")
    knowledge = triage.KnowledgeBase()
    exported = str(tmp_path / "kb.json")
    assert knowledge.export(exported) >= 1
    assert knowledge.export_cases(str(tmp_path / "cases")) == 1
    other = triage.KnowledgeBase(str(tmp_path / "other.json"))
    assert other.import_file(exported) >= 1 and other.data["patterns"]
