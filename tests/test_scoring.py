"""Score design: attack surface, separate production / test / density numbers (C-20, C-21)."""
from secure_repo.core.events import EventBus
from secure_repo.core.scanner import Scanner, ScanOptions
from secure_repo.core.scoring import compute_score
from secure_repo.core.summary import split_scores
from secure_repo.core.workspace import Target
from secure_repo.report import formats
from tests.conftest import write


def finding(rule, severity, file="app.py", **extra):
    return dict({"rule_id": rule, "severity": severity, "file": file}, **extra)


def test_the_same_weakness_in_many_files_costs_more_than_in_one_file():
    one_file = compute_score([finding("SR-PY-011", "medium") for _ in range(20)])
    many_files = compute_score([finding("SR-PY-011", "medium", file=f"app/f{i}.py") for i in range(20)])
    assert many_files["penalty"] > one_file["penalty"] and many_files["score"] < one_file["score"]


def test_a_single_occurrence_is_unaffected_by_the_surface_term():
    single = compute_score([finding("SR-PY-011", "medium", file="a.py")])
    twin = compute_score([finding("SR-PY-011", "medium", file="a.py"), finding("SR-PY-011", "medium", file="a.py")])
    assert single["penalty"] < twin["penalty"]                       # repeats still add (diminishing) penalty
    spread = compute_score([finding("SR-PY-011", "medium", file="a.py"), finding("SR-PY-011", "medium", file="b.py")])
    assert twin["penalty"] < spread["penalty"] < 2 * single["penalty"] * 1.5


def test_surface_penalty_grows_slowly_so_big_projects_do_not_saturate_instantly():
    hundred = compute_score([finding("SR-PY-011", "medium", file=f"f{i}.py") for i in range(100)])
    single = compute_score([finding("SR-PY-011", "medium")])["penalty"]
    assert 5 * single < hundred["penalty"] < 15 * single       # clearly worse than one occurrence, still bounded


def make_report(tmp_path):
    root = str(tmp_path / "r")
    write(root, "app/db.py", "import os\nfrom flask import request\n\ndef run():\n    os.system(request.args.get('c'))\n")
    write(root, "tests/test_db.py", "import os\nfrom flask import request\n\ndef test_run():\n    os.system(request.args.get('c'))\n")
    for index in range(30):
        write(root, f"app/util{index}.py", "def helper(value):\n    return value\n" * 20)
    report, folder = Scanner(ScanOptions(offline=True, trust_repo_config=True, output_dir=str(tmp_path / "out")),
                             EventBus()).run(Target.parse(root))
    return report, folder


def test_the_report_carries_production_tests_and_density(tmp_path):
    report, folder = make_report(tmp_path)
    scores = report["summary"]["scores"]
    assert set(scores) == {"production", "tests", "density"}
    assert scores["production"]["grade"] in ("D", "F") and scores["production"]["score"] <= 59
    assert scores["tests"]["grade"] in ("D", "F", "C", "B", "A") and 0 <= scores["tests"]["score"] <= 100
    density = scores["density"]
    assert density["kloc"] > 1 and density["findings"] >= 1 and density["serious"] >= 1
    assert density["serious_per_kloc"] == round(density["serious"] / density["kloc"], 2)
    with open(f"{folder}/summary.md", encoding="utf-8") as handle:
        text = handle.read()
    assert "Production code" in text and "Test code" in text and "per 1,000 lines" in text


def test_density_ignores_documentation_and_test_findings():
    report = {"languages": {"Python": {"lines": 2000}, "Markdown": {"lines": 98000}}}
    findings = [finding("A", "high", source="code", status="open"),
                finding("B", "high", source="code", status="open", in_test=True),
                finding("C", "low", source="hygiene", status="open")]
    density = split_scores(report, findings)["density"]
    assert density["kloc"] == 2.0 and density["findings"] == 1 and density["per_kloc"] == 0.5


def test_split_score_lines_are_skipped_for_old_reports():
    assert formats.split_score_lines({"score": 90}) == []
