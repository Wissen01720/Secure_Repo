"""Standards baseline (October 2026): OWASP Top 10:2025, OWASP LLM 2025 and Agentic 2026, CWE Top 25 2025, EOL runtimes."""
import os
import re
from datetime import date

from secure_repo.core import compliance, runtimes
from secure_repo.core.events import EventBus
from secure_repo.core.models import (CWE_TOP25_2025, OWASP_TOP10_2025, cwe_top25_rank, owasp_2025_code,
                                     owasp_2025_label)
from secure_repo.core.rules import RULES_BY_ID
from secure_repo.core.scanner import Scanner, ScanOptions
from secure_repo.core.workspace import Target
from tests.conftest import write

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def scan(tmp_path, files, **options):
    root = str(tmp_path / "repo")
    for name, content in files.items():
        write(root, name, content)
    options.setdefault("offline", True)
    options.setdefault("trust_repo_config", True)
    report, _folder = Scanner(ScanOptions(output_dir=str(tmp_path / "out"), **options), EventBus()).run(Target.parse(root))
    return report


# ------------------------------------------------------------------ OWASP Top 10:2025 and CWE Top 25
def test_owasp_2025_has_ten_categories_with_the_new_ones():
    assert list(OWASP_TOP10_2025) == [f"A{n:02d}" for n in range(1, 11)]
    assert OWASP_TOP10_2025["A03"]["name"] == "Software Supply Chain Failures"
    assert OWASP_TOP10_2025["A10"]["name"] == "Mishandling of Exceptional Conditions"
    mapped = [code for info in OWASP_TOP10_2025.values() for code in info["from_2021"]]
    assert sorted(mapped) == sorted(f"A{n:02d}" for n in range(1, 11))          # every 2021 category lands somewhere


def test_a_rule_can_name_its_2025_category_when_2021_has_no_equivalent():
    assert owasp_2025_code("A09", "A10") == "A10"
    assert owasp_2025_code("A03") == "A05"
    assert owasp_2025_label("A09", "A10") == "A10:2025 Mishandling of Exceptional Conditions"
    rule = RULES_BY_ID["SR-PY-028"]
    assert rule.to_dict()["owasp_2025"] == "A10"
    assert any("/Top10/2025/A10_2025-Mishandling_of_Exceptional_Conditions/" in link for link in rule.reference_links())


def test_cwe_top_25_2025_ranks():
    assert len(CWE_TOP25_2025) == 25 and cwe_top25_rank("CWE-79") == 1 and cwe_top25_rank("CWE-862") == 4
    assert cwe_top25_rank("CWE-798") == 0 and cwe_top25_rank("") == 0


def test_findings_and_summary_carry_both_owasp_editions_and_the_cwe_rank(tmp_path):
    report = scan(tmp_path, {"app.py": "import os\nfrom flask import request\nos.system(request.args.get('c'))\n",
                             "svc.py": "def f(user):\n    try:\n        return check(user)\n    except Exception:\n        pass\n"})
    injection = next(f for f in report["findings"] if f["cwe"] == "CWE-78")
    assert injection["owasp"] == "A03" and injection["owasp_2025"] == "A05" and injection["cwe_top25"] == 9
    swallowed = next(f for f in report["findings"] if f["rule_id"] == "SR-PY-028")
    assert swallowed["owasp_2025"] == "A10" and "exceptions" in swallowed["tags"]
    summary = report["summary"]
    assert summary["by_owasp_2025"]["A05"] >= 1 and summary["by_owasp_2025"]["A10"] == 1
    assert summary["cwe_top25_findings"] >= 1
    assert "A10" in report["owasp_top10_2025"]


def test_the_owasp_framework_is_the_2025_edition_and_the_old_one_stays_available(tmp_path):
    assert compliance.FRAMEWORKS["owasp"].version == "2025"
    assert [c.id for c in compliance.FRAMEWORKS["owasp"].controls] == [f"A{n:02d}:2025" for n in range(1, 11)]
    assert "owasp-2021" in compliance.FRAMEWORKS and compliance.FRAMEWORKS["owasp-2021"].version == "2021"
    assert compliance.resolve_frameworks(["OWASP2021"]) == ["owasp-2021"]
    assert "owasp-2021" not in compliance.resolve_frameworks(["all"])            # `all` does not duplicate the editions
    report = scan(tmp_path, {"svc.py": "def f(user):\n    try:\n        return check(user)\n    except Exception:\n        pass\n"},
                  compliance=True, frameworks=["owasp"])
    controls = {c["id"]: c for c in report["compliance"]["frameworks"][0]["controls"]}
    assert controls["A10:2025"]["status"] == "warning" and controls["A10:2025"]["findings"]
    assert controls["A05:2025"]["status"] == "pass"


# ------------------------------------------------------------------ AI frameworks
def test_ai_frameworks_exist_with_all_ten_controls():
    llm, agentic = compliance.FRAMEWORKS["owasp-llm"], compliance.FRAMEWORKS["owasp-agentic"]
    assert [c.id for c in llm.controls] == [f"LLM{n:02d}" for n in range(1, 11)]
    assert [c.id for c in agentic.controls] == [f"ASI{n:02d}" for n in range(1, 11)]
    assert llm.requires_ai and agentic.requires_ai
    assert sum(1 for c in llm.controls if c.manual) >= 5            # what code cannot show is left to people


def test_ai_frameworks_are_offered_only_to_repositories_that_use_ai(tmp_path):
    plain = scan(tmp_path, {"app.py": "print('hello')\n"}, compliance=True)
    ids = {f["id"] for f in plain["compliance"]["frameworks"]}
    assert "owasp" in ids and "owasp-llm" not in ids and "owasp-agentic" not in ids and plain["compliance"]["ai_stack"] is False


def test_an_ai_repository_gets_the_llm_and_agentic_evidence(tmp_path):
    code = ("import os\nfrom openai import OpenAI\n\nclient = OpenAI()\n\n"
            "def run(q):\n    reply = client.chat.completions.create(model='m', messages=[{'role': 'user', 'content': q}])\n"
            "    return eval(reply.choices[0].message.content)\n")
    report = scan(tmp_path, {"app.py": code, "requirements.txt": "openai==1.0.0\n"}, compliance=True)
    assert report["compliance"]["ai_stack"] is True
    frameworks = {f["id"]: f for f in report["compliance"]["frameworks"]}
    assert {"owasp-llm", "owasp-agentic"} <= set(frameworks)
    llm = {c["id"]: c for c in frameworks["owasp-llm"]["controls"]}
    agentic = {c["id"]: c for c in frameworks["owasp-agentic"]["controls"]}
    assert llm["LLM05"]["status"] == "fail" and agentic["ASI05"]["status"] == "fail"
    assert llm["LLM09"]["status"] == "manual"


def test_choosing_an_ai_framework_for_a_plain_repository_explains_why_it_is_left_out(tmp_path):
    report = scan(tmp_path, {"app.py": "print('hello')\n"}, compliance=True, frameworks=["llm", "pci-dss"])
    assert [f["id"] for f in report["compliance"]["frameworks"]] == ["pci-dss"]
    skipped = report["compliance"]["not_applicable"]
    assert [s["id"] for s in skipped] == ["owasp-llm"] and "No AI or LLM libraries" in skipped[0]["reason"]


def test_detect_ai_stack_uses_packages_and_ai_rules():
    assert compliance.detect_ai_stack([{"name": "LangChain"}], []) is True
    assert compliance.detect_ai_stack([{"name": "flask"}], [{"rule_id": "SR-AI-004"}]) is True
    assert compliance.detect_ai_stack([{"name": "flask"}], [{"rule_id": "SR-PY-001"}]) is False


def test_every_ai_tag_used_by_a_rule_is_checked_by_some_control():
    checked = {tag for fw in ("owasp-llm", "owasp-agentic") for c in compliance.FRAMEWORKS[fw].controls for tag in c.tags}
    used = {tag for rule in RULES_BY_ID.values() if rule.id.startswith("SR-AI-") for tag in rule.tags
            if tag.startswith(("llm-", "agent-", "mcp"))}
    assert used <= checked, used - checked


def test_other_standards_carry_their_current_editions():
    assert compliance.FRAMEWORKS["pci-dss"].version == "4.0.1"
    assert "Amendment 1:2024" in compliance.FRAMEWORKS["iso27001"].version
    assert "v1.2 draft" in compliance.FRAMEWORKS["nist-ssdf"].version
    assert "proposal" in compliance.FRAMEWORKS["hipaa"].version
    assert {"PS.2", "RV.2"} <= {c.id for c in compliance.FRAMEWORKS["nist-ssdf"].controls}
    assert "A.5.21" in {c.id for c in compliance.FRAMEWORKS["iso27001"].controls}


# ------------------------------------------------------------------ end-of-life runtimes
TODAY = date(2026, 10, 25)


def test_python_and_node_versions_past_end_of_life_are_found():
    assert runtimes.scan_text(".python-version", "3.9.18\n", TODAY) == [(1, "python", "3.9.18", "2025-10-31")]
    assert runtimes.scan_text(".python-version", "3.10\n", TODAY)[0][3] == "2026-10-01"      # the line closed this month
    assert runtimes.scan_text(".python-version", "3.14\n", TODAY) == []
    assert runtimes.scan_text(".nvmrc", "v18.20.0\n", TODAY)[0][1:3] == ("node", "v18.20.0")
    assert runtimes.scan_text("runtime.txt", "python-3.8.10\n", TODAY)[0][1] == "python"
    assert runtimes.scan_text(".tool-versions", "nodejs 20.1.0\nruby 3.3.0\n", TODAY)[0][1] == "node"
    assert runtimes.scan_text("services/api/Dockerfile", "FROM --platform=linux/amd64 node:12-alpine AS build\n", TODAY)[0][1] == "node"
    assert runtimes.scan_text("Dockerfile", "FROM registry.example.com/team/python:3.11-slim\n", TODAY) == []


def test_a_ci_matrix_that_also_tests_a_supported_release_is_not_flagged():
    mixed = "jobs:\n  t:\n    steps:\n      - with:\n          python-version: [\"3.8\", \"3.9\", \"3.13\"]\n"
    assert runtimes.scan_text(".github/workflows/ci.yml", mixed, TODAY) == []
    only_old = "jobs:\n  t:\n    steps:\n      - with:\n          python-version: 3.7.10\n"
    assert [i[1:3] for i in runtimes.scan_text(".github/workflows/ci.yml", only_old, TODAY)] == [("python", "3.7.10")]


def test_the_scanner_reports_the_runtime_and_the_date(tmp_path):
    report = scan(tmp_path, {"Dockerfile": "FROM python:3.9-slim\nUSER app\n", ".nvmrc": "22\n"})
    finds = [f for f in report["findings"] if f["rule_id"] == "SR-DEP-011"]
    assert len(finds) == 1 and finds[0]["file"] == "Dockerfile" and "Python 3.9" in finds[0]["title"]
    assert finds[0]["extra"]["end_of_life"] == "2025-10-31" and "no longer receives security fixes" in finds[0]["detail"]


def test_the_project_itself_requires_a_supported_python():
    with open(os.path.join(ROOT, "pyproject.toml"), encoding="utf-8") as handle:
        pyproject = handle.read()
    assert 'requires-python = ">=3.11"' in pyproject and "tomli" not in pyproject
    assert "Python :: 3.14" in pyproject and "Python :: 3.10" not in pyproject
    with open(os.path.join(ROOT, ".github", "workflows", "ci.yml"), encoding="utf-8") as handle:
        ci = handle.read()
    assert re.search(r'python: \["3\.11", "3\.14"\]', ci)


# ------------------------------------------------------------------ the new rules in context
def test_ai_rules_detect_the_patterns_and_leave_safe_code_alone(tmp_path):
    report = scan(tmp_path, {
        "agent.py": ("from transformers import AutoModel\nimport torch\nm = AutoModel.from_pretrained('x', trust_remote_code=True)\n"
                     "s = torch.load('w.bin', weights_only=False)\n"),
        ".mcp.json": '{"mcpServers": {"a": {"command": "npx", "args": ["-y", "@acme/server"]}}}\n',
        "CLAUDE.md": "# Rules\nRun tests.\u200b\n",
        "safe.py": "import torch\ns = torch.load('w.bin', weights_only=True)\n",
    })
    by_file = {}
    for finding in report["findings"]:
        by_file.setdefault(finding["file"], set()).add(finding["rule_id"])
    assert {"SR-AI-002", "SR-AI-003"} <= by_file["agent.py"]
    assert "SR-AI-006" in by_file[".mcp.json"] and "SR-AI-010" in by_file["CLAUDE.md"]
    assert not any(rule.startswith("SR-AI") for rule in by_file.get("safe.py", ()))


def test_tarfile_rules_follow_the_extraction_filters():
    unsafe = "import tarfile\nwith tarfile.open(p) as tf:\n    tf.extractall(d)\n"
    safe = "import tarfile\nwith tarfile.open(p) as tf:\n    tf.extractall(d, filter='data')\n"
    trusting = "import tarfile\nwith tarfile.open(p) as tf:\n    tf.extractall(d, filter='fully_trusted')\n"
    rule26, rule27 = RULES_BY_ID["SR-PY-026"], RULES_BY_ID["SR-PY-027"]
    assert rule26.regex.search(unsafe) and not rule26.regex.search(safe) and not rule26.regex.search(trusting)
    assert not rule27.regex.search(safe) and rule27.regex.search(trusting)
    assert not rule26.regex.search("import start\nstart.extract(d)\n") and not rule26.regex.search("guitar.extractall(x)")


def test_weekly_dependency_audit_is_pinned_read_only_and_online():
    with open(os.path.join(ROOT, ".github", "workflows", "dependency-audit.yml"), encoding="utf-8") as handle:
        workflow = handle.read()
    assert "schedule:" in workflow and "cron:" in workflow and "--offline" not in workflow
    assert re.search(r"^permissions:\s*\n\s+contents: read", workflow, re.MULTILINE)
    assert "--fail-on high" in workflow and "pull_request_target" not in workflow
    for reference in re.findall(r"uses:\s*(\S+)", workflow):
        assert re.fullmatch(r"[\w./-]+@[0-9a-f]{40}", reference), reference
