"""Regression tests: the audited repository must not be able to shape its own result (review items C-01..C-04, C-18, C-28)."""
import json
import os
import shutil
import subprocess

import pytest

from secure_repo.core.config import is_within, load_config
from secure_repo.core.events import EventBus
from secure_repo.core.scanner import Scanner, ScanOptions
from secure_repo.core.workspace import Target
from tests.conftest import write

BASE = ("import os\nfrom flask import request\n\n"
        "def run():\n    os.system(request.args.get('c'))\n    eval(request.args.get('x'))\n")
HOSTILE_CONFIG = '[rules]\ndisable = ["SR-PY-005"]\n[rules.severity]\n"SR-PY-001" = "info"\n'
GIT_ENV = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.com",
               GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.com")


def git(root, *args):
    subprocess.run(["git", *args], cwd=root, env=GIT_ENV, check=True, capture_output=True)


def make_git_repo(root, files):
    for rel, content in files.items():
        write(root, rel, content)
    git(root, "init", "-q", "-b", "main")
    git(root, "add", "-A")
    git(root, "commit", "-qm", "init")


def scan(root, branch=None, **options):
    options.setdefault("offline", True)
    scanner = Scanner(ScanOptions(**options), EventBus())
    report, _ = scanner.run(Target.parse(root, branch), write_reports=False)
    return report


def open_findings(report, rule_id=None):
    return [f for f in report["findings"] if f["status"] == "open" and (rule_id is None or f["rule_id"] == rule_id)]


needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")


# ---------------------------------------------------------------------- C-01
@needs_git
def test_hostile_config_is_ignored_for_other_branches(tmp_path):
    root = str(tmp_path / "repo")
    make_git_repo(root, {"app.py": BASE, ".securerepo.toml": HOSTILE_CONFIG})
    git(root, "checkout", "-q", "-b", "elsewhere")
    report = scan(root, branch="main")  # not the working tree -> untrusted
    influence = report["analysis"]["repo_influence"]
    assert report["meta"]["mode"] == "branch-export" and influence["trusted"] is False
    assert open_findings(report, "SR-PY-005") and open_findings(report, "SR-PY-001")
    assert {f["severity"] for f in open_findings(report, "SR-PY-001")} == {"critical"}
    assert any(".securerepo.toml" in item for item in influence["ignored"])
    assert report["summary"]["by_severity"]["critical"] >= 2


def test_hostile_config_is_ignored_in_plain_folders(tmp_path):
    root = str(tmp_path / "folder")
    write(root, "app.py", BASE)
    write(root, ".securerepo.toml", HOSTILE_CONFIG)
    report = scan(root)  # not a Git repository -> untrusted by default
    assert report["analysis"]["repo_influence"]["trusted"] is False
    assert open_findings(report, "SR-PY-005")


@needs_git
def test_trusted_config_is_applied_but_never_hides_its_effect(tmp_path):
    root = str(tmp_path / "repo")
    make_git_repo(root, {"app.py": BASE, ".securerepo.toml": HOSTILE_CONFIG})
    report = scan(root)  # working tree of a local repository -> trusted
    influence = report["analysis"]["repo_influence"]
    assert influence["trusted"] is True
    hidden = [f for f in report["findings"] if f["rule_id"] == "SR-PY-005"]
    assert hidden and all(f["status"] == "disabled_by_config" for f in hidden)  # kept, never deleted
    assert [r["rule_id"] for r in influence["disabled_rules"]] == ["SR-PY-005"]
    assert influence["disabled_rules"][0]["from"] == "repo"
    override = influence["severity_overrides"][0]
    assert (override["rule_id"], override["from_severity"], override["to_severity"]) == ("SR-PY-001", "critical", "info")
    assert influence["score_without_repo_content"] < influence["score_with_repo_content"]
    assert influence["material"] is True and influence["active"] is True
    assert report["summary"]["score"] == influence["score_with_repo_content"]
    assert any(f["rule_id"] == "SR-PY-005" for f in report["findings"] if f["status"] == "disabled_by_config")


@needs_git
def test_analyst_can_force_trust_or_distrust(tmp_path):
    root = str(tmp_path / "repo")
    make_git_repo(root, {"app.py": BASE, ".securerepo.toml": HOSTILE_CONFIG})
    assert scan(root, trust_repo_config=False)["analysis"]["repo_influence"]["trusted"] is False
    assert open_findings(scan(root, trust_repo_config=False), "SR-PY-005")
    folder = str(tmp_path / "folder")
    write(folder, "app.py", BASE)
    write(folder, ".securerepo.toml", HOSTILE_CONFIG)
    forced = scan(folder, trust_repo_config=True)
    assert forced["analysis"]["repo_influence"]["trusted"] is True
    assert not open_findings(forced, "SR-PY-005")


def test_repo_custom_rules_and_exclusions_need_trust(tmp_path):
    root = str(tmp_path / "folder")
    write(root, "app.py", BASE)
    write(root, "secret_zone/handler.py", BASE)
    write(root, ".securerepo.toml", '[scan]\nexclude = ["secret_zone/*"]\n[[custom_rules]]\nid = "EVIL-001"\n'
                                    'title = "x"\nseverity = "low"\npattern = "(a+)+$"\ncontext = "raw"\n')
    untrusted = scan(root)
    assert any(f["file"] == "secret_zone/handler.py" for f in open_findings(untrusted))
    assert untrusted["analysis"]["custom_rules"] == []
    trusted = scan(root, trust_repo_config=True)
    assert not any(f["file"] == "secret_zone/handler.py" for f in trusted["findings"])
    excluded = trusted["analysis"]["repo_influence"]["excluded_by_config"]
    assert excluded["files"] == 1 and excluded["sample"] == ["secret_zone/handler.py"]  # declared, not hidden
    assert excluded["patterns"][0]["from"] == "repo"


# ---------------------------------------------------------------------- C-02
@needs_git
def test_shared_triage_file_cannot_silence_findings_in_untrusted_repos(tmp_path):
    root = str(tmp_path / "repo")
    make_git_repo(root, {"app.py": BASE})
    first = scan(root, learning=True)
    decisions = {f["fingerprint"]: {"status": "false_positive", "reason": "planted", "rule_id": f["rule_id"]}
                 for f in first["findings"] if f["severity"] == "critical"}
    write(root, ".securerepo/triage.json", json.dumps({"decisions": decisions}))
    git(root, "add", "-A")
    git(root, "commit", "-qm", "planted triage")
    git(root, "checkout", "-q", "-b", "elsewhere")
    untrusted = scan(root, branch="main")
    assert open_findings(untrusted, "SR-PY-001") and open_findings(untrusted, "SR-PY-005")
    assert any("triage.json" in item for item in untrusted["analysis"]["repo_influence"]["ignored"])
    git(root, "checkout", "-q", "main")
    trusted = scan(root)
    influence = trusted["analysis"]["repo_influence"]
    assert influence["repo_decisions"] >= 2  # applied, but attributed to the repository and counted
    assert influence["score_without_repo_content"] < trusted["summary"]["score"]
    origins = {f["triage"]["origin"] for f in trusted["findings"] if f["status"] == "false_positive"}
    assert origins == {"repo-decision"}


# ---------------------------------------------------------------------- C-03 / C-18
def test_ignore_file_marker_is_never_honoured_and_is_reported(tmp_path):
    root = str(tmp_path / "folder")
    write(root, "evil.py", "# securerepo:ignore-file\n" + BASE)
    report = scan(root, trust_repo_config=True)
    assert open_findings(report, "SR-PY-001") and open_findings(report, "SR-PY-005")
    assert report["analysis"]["repo_influence"]["ignore_file_markers"] == ["evil.py"]


# ---------------------------------------------------------------------- C-04
def test_nosec_inside_a_string_does_not_suppress(tmp_path):
    root = str(tmp_path / "folder")
    write(root, "app.py", BASE.replace("eval(request.args.get('x'))", "eval(request.args.get('x')); tag = 'nosec'"))
    report = scan(root, trust_repo_config=True)
    assert open_findings(report, "SR-PY-001")
    assert not [f for f in report["findings"] if f["status"] == "suppressed_inline"]


def test_nosec_comments_are_scoped_to_rule_ids_and_recorded(tmp_path):
    root = str(tmp_path / "folder")
    write(root, "app.py", "import os\nfrom flask import request\n\ndef run():\n"
                          "    os.system(request.args.get('c'))  # nosec SR-PY-999 wrong rule\n"
                          "    eval(request.args.get('x'))  # nosec SR-PY-001 reviewed, input is validated upstream\n"
                          "    os.system(request.args.get('d'))  # nosec\n")
    report = scan(root, trust_repo_config=True)
    by_line = {f["line"]: f for f in report["findings"] if f["rule_id"] in ("SR-PY-001", "SR-PY-005")}
    assert by_line[5]["status"] == "open"                       # a nosec for another rule does not apply
    assert by_line[6]["status"] == "suppressed_inline" and "reviewed" in by_line[6]["triage"]["reason"]
    assert by_line[7]["status"] == "suppressed_inline" and by_line[7]["triage"]["rule_ids"] == []
    influence = report["analysis"]["repo_influence"]
    assert influence["inline"] == 2 and influence["inline_without_rule_id"] == 1
    suppressed_md = "findings/suppressed.md"
    assert suppressed_md and any(f["status"] == "suppressed_inline" for f in report["findings"])


def test_nosec_comments_are_ignored_in_untrusted_repos(tmp_path):
    root = str(tmp_path / "folder")
    write(root, "app.py", BASE.replace("eval(request.args.get('x'))", "eval(request.args.get('x'))  # nosec"))
    report = scan(root)  # folder -> untrusted
    assert open_findings(report, "SR-PY-001")
    influence = report["analysis"]["repo_influence"]
    assert any("inline suppression" in item for item in influence["ignored"])


def test_inline_suppression_works_in_non_masked_languages_only_inside_comments(tmp_path):
    root = str(tmp_path / "folder")
    write(root, "Dockerfile", "FROM python:latest  # nosec SR-DOCKER-001 pinned by the registry mirror\n"
                              "USER app\nRUN echo 'nosec' && curl -sL https://get.example.io | sh\n")
    report = scan(root, trust_repo_config=True)
    status = {f["rule_id"]: f["status"] for f in report["findings"] if f["rule_id"] in ("SR-DOCKER-001", "SR-SH-001")}
    assert status["SR-DOCKER-001"] == "suppressed_inline"
    assert status["SR-SH-001"] == "open"  # 'nosec' only appears inside a quoted string


def test_suppressed_findings_are_listed_in_the_audit_trail(tmp_path):
    root = str(tmp_path / "folder")
    write(root, "app.py", BASE.replace("eval(request.args.get('x'))", "eval(request.args.get('x'))  # nosec"))
    out = str(tmp_path / "reports")
    scanner = Scanner(ScanOptions(offline=True, trust_repo_config=True, output_dir=out), EventBus())
    report, folder = scanner.run(Target.parse(root))
    text = open(os.path.join(folder, "findings", "suppressed.md"), encoding="utf-8").read()
    assert "suppressed_inline" in text and "inline" in text
    quality = open(os.path.join(folder, "quality.md"), encoding="utf-8").read()
    assert "Influence of the audited repository" in quality


# ---------------------------------------------------------------------- C-28
def test_path_prefix_comparison_uses_path_components(tmp_path):
    root = str(tmp_path / "app")
    assert is_within(os.path.join(root, "sub", ".securerepo.toml"), root)
    assert is_within(root, root)
    assert not is_within(str(tmp_path / "app-old" / ".securerepo.toml"), root)


def test_untrusted_loading_never_reads_the_repo_file(tmp_path):
    root = str(tmp_path / "repo")
    write(root, ".securerepo.toml", HOSTILE_CONFIG)
    config = load_config(root, trust_repo=False)
    assert config.disable == [] and config.severity == {}
    assert config.ignored_source and config.ignored_source.endswith(".securerepo.toml")
    trusted = load_config(root, trust_repo=True)
    assert trusted.disable == ["SR-PY-005"] and trusted.repo_disable == ["SR-PY-005"]


def test_cli_trust_flags_are_mutually_exclusive():
    from secure_repo.cli.main import build_parser

    parser = build_parser()
    assert parser.parse_args(["scan", ".", "--trust-repo-config"]).trust_repo_config is True
    assert parser.parse_args(["scan", ".", "--ignore-repo-config"]).ignore_repo_config is True
    with pytest.raises(SystemExit):
        parser.parse_args(["scan", ".", "--trust-repo-config", "--ignore-repo-config"])
