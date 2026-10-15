"""Private packages, registry limits, --baseline, --since and --fail-on semantics (C-30, C-32, C-49). No real network."""
import os
import subprocess
import urllib.error

import pytest

from secure_repo.cli import main as cli
from secure_repo.core import intel, netio, resolver
from secure_repo.core.events import EventBus
from secure_repo.core.scanner import Scanner, ScanOptions
from secure_repo.core.workspace import Target
from tests.conftest import write

VULNERABLE = "import os\nfrom flask import request\n\ndef run():\n    os.system(request.args.get('c'))\n"


@pytest.fixture()
def world(monkeypatch):
    """A fake public internet: records every request and answers like OSV.dev and deps.dev."""
    seen = []

    def fake(url, payload=None, timeout=20, cache=False):
        seen.append((url, payload))
        if url == intel.OSV_BATCH_URL:
            return {"results": [{} for _ in payload["queries"]]}
        if url.endswith(":dependencies"):
            return {"nodes": []}
        if "/versions/" in url:
            return {"licenses": ["MIT"]}
        if "/packages/" in url:
            if "ghost-internal" in url:
                raise urllib.error.HTTPError(url, 404, "not found", {}, None)
            return {"versions": [{"versionKey": {"version": "1.2.3"}, "isDefault": True}]}
        raise urllib.error.URLError("unexpected " + url)

    monkeypatch.setattr(intel, "_http_json", fake)
    monkeypatch.setattr(resolver, "_http_json", fake)
    return seen


def names_sent(seen):
    sent = set()
    for url, payload in seen:
        if payload:
            sent.update(q["package"]["name"] for q in payload["queries"])
        elif "/packages/" in url:
            sent.add(url.split("/packages/")[1].split("/")[0].split(":")[0])
    return sent


def scan(root, **options):
    options.setdefault("trust_repo_config", True)
    options.setdefault("learning", False)
    scanner = Scanner(ScanOptions(**options), EventBus())
    report, _ = scanner.run(Target.parse(root), write_reports=False)
    return report, scanner


def python_repo(tmp_path, requirements):
    root = str(tmp_path / "r")
    write(root, "requirements.txt", requirements)
    write(root, "app.py", "print('hi')\n")
    return root


# ---------------------------------------------------------------------- private packages (C-30)
def test_private_names_never_reach_any_service(tmp_path, world):
    root = python_repo(tmp_path, "acme-core>=1.0\nacme-billing==2.0.0\nflask>=2.0\nrequests==2.31.0\n")
    report, _ = scan(root, private=["acme-*"])
    sent = names_sent(world)
    assert "flask" in sent and "requests" in sent
    assert not any(name.startswith("acme") for name in sent), sent
    private = {d["name"]: d["private"] for d in report["dependencies"]}
    assert private["acme-core"] and private["acme-billing"] and not private["flask"]


def test_private_patterns_can_come_from_the_trusted_project_configuration(tmp_path, world):
    root = python_repo(tmp_path, "acme-core>=1.0\nflask>=2.0\n")
    write(root, ".securerepo.toml", '[intel]\nprivate = ["ACME-*"]\n')
    scan(root)
    assert "acme-core" not in names_sent(world) and "flask" in names_sent(world)


def test_an_untrusted_repository_cannot_hide_its_dependencies_from_the_scan(tmp_path, world):
    root = python_repo(tmp_path, "evil-lib==1.0.0\n")
    write(root, ".securerepo.toml", '[intel]\nprivate = ["*"]\n')
    report, _ = scan(root, trust_repo_config=False)
    assert "evil-lib" in names_sent(world)                       # the repo's own list is ignored: the lookup still happens
    assert not any(d["private"] for d in report["dependencies"])


def test_no_registry_still_checks_osv_but_never_asks_the_registries(tmp_path, world):
    root = python_repo(tmp_path, "flask>=2.0\nrequests==2.31.0\n")
    report, _ = scan(root, no_registry=True)
    registry_urls = [url for url, _p in world if "deps.dev" in url]
    assert registry_urls == []
    assert any(url == intel.OSV_BATCH_URL for url, _p in world)
    assert {d["name"]: d["version"] for d in report["dependencies"]}["flask"] is None     # not resolved without registries


def test_confusion_check_is_opt_in_and_reports_names_that_exist_publicly(tmp_path, world, monkeypatch):
    root = python_repo(tmp_path, "six==1.16.0\nghost-internal==1.0.0\n")
    plain, _ = scan(root, private=["six", "ghost-internal"])
    assert not [f for f in plain["findings"] if f["rule_id"] == "SR-DEP-010"]
    assert not any("six" in url for url, _p in world)
    checked, _ = scan(root, private=["six", "ghost-internal"], check_confusion=True)
    hits = [f for f in checked["findings"] if f["rule_id"] == "SR-DEP-010"]
    assert [f["snippet"] for f in hits] == ["six"] and hits[0]["severity"] == "high"
    assert "exists in the public" in hits[0]["detail"]


# ---------------------------------------------------------------------- limits are reported (C-32)
def test_registry_limits_are_reported_in_the_report(tmp_path, world):
    root = python_repo(tmp_path, "".join(f"lib{i}>=1.0\n" for i in range(5)))
    report, _ = scan(root, max_registry=2, max_graph=1, max_enrich=1)
    notes = report["analysis"]["not_analyzed"]["intel"]
    assert any("3 dependencies were not resolved against the registries because of the limit (2)" in n for n in notes)
    assert any("--max-registry" in n for n in notes) and any("--max-graph" in n for n in notes)
    assert any("--max-enrich" in n for n in notes)
    assert report["analysis"]["network"]["notes"] == notes


def test_failed_osv_batches_show_up_in_the_report(tmp_path, monkeypatch, world):
    def fake(url, payload=None, timeout=20, cache=False):
        if url == intel.OSV_BATCH_URL:
            raise urllib.error.URLError("proxy reset")
        return {"versions": []}

    monkeypatch.setattr(intel, "_http_json", fake)
    root = python_repo(tmp_path, "flask==2.0.1\n")
    report, _ = scan(root)
    assert report["dependency_summary"]["online"] is False


# ---------------------------------------------------------------------- baseline (C-49)
def report_path(tmp_path, root, name="base"):
    report, folder = Scanner(ScanOptions(offline=True, trust_repo_config=True, learning=False,
                                         output_dir=str(tmp_path / name)), EventBus()).run(Target.parse(root))
    return report, os.path.join(folder, "report.json")


def test_baseline_marks_existing_findings_and_reports_only_new_ones(tmp_path):
    root = str(tmp_path / "r")
    write(root, "app/old.py", VULNERABLE)
    _first, baseline = report_path(tmp_path, root)
    write(root, "app/new.py", VULNERABLE.replace("run", "run_new"))
    report, _ = scan(root, offline=True, baseline=baseline)
    states = {(f["file"], f["extra"]["baseline"]) for f in report["findings"] if f["rule_id"] == "SR-PY-005"}
    assert states == {("app/old.py", "existing"), ("app/new.py", "new")}
    summary = report["summary"]["baseline"]
    assert summary["new"] >= 1 and summary["existing"] >= 1 and sum(summary["new_by_severity"].values()) == summary["new"]
    assert report["meta"]["baseline"]["file"] == "report.json"


def test_fail_on_with_a_baseline_only_counts_new_findings(tmp_path, capsys):
    root = str(tmp_path / "r")
    write(root, "app/old.py", VULNERABLE)
    out = str(tmp_path / "out")
    args = ["--no-update-check", "scan", root, "--offline", "--yes", "--plain", "--no-menu", "--trust-repo-config",
            "-o", out, "--fail-on", "medium"]
    assert cli.main(args) == 3                                          # the existing flaw fails a plain gate...
    baseline = os.path.join(out, open(os.path.join(out, "latest.txt")).read().strip(), "report.json")
    capsys.readouterr()
    assert cli.main(args + ["--baseline", baseline]) == 0               # ...but not against the baseline
    write(root, "app/new.py", VULNERABLE.replace("run", "run_new"))
    assert cli.main(args + ["--baseline", baseline]) == 3               # a new one does
    assert "new finding(s)" in capsys.readouterr().out


def test_sarif_carries_the_baseline_state(tmp_path):
    root = str(tmp_path / "r")
    write(root, "app/old.py", VULNERABLE)
    _r, baseline = report_path(tmp_path, root)
    write(root, "app/new.py", VULNERABLE.replace("run", "run_new"))
    from secure_repo.report import formats

    report, _ = scan(root, offline=True, baseline=baseline)
    states = {r["baselineState"] for r in formats.sarif(report)["runs"][0]["results"] if "baselineState" in r}
    assert states == {"new", "unchanged"}


def test_fail_on_ignores_false_positives_and_accepted_risks(tmp_path):
    root = str(tmp_path / "r")
    write(root, "app.py", VULNERABLE)
    write(root, ".securerepo.toml", '[rules]\ndisable = ["SR-PY-005"]\n')
    code = cli.main(["--no-update-check", "scan", root, "--offline", "--yes", "--plain", "--no-menu", "--trust-repo-config",
                     "-o", str(tmp_path / "out"), "--fail-on", "high"])
    assert code == 0                                    # the only critical finding was disabled by configuration


@pytest.mark.parametrize("content", ["not json", '{"findings": [{"id": "SR-1"}]}', "[1, 2]"])
def test_an_invalid_baseline_is_rejected_before_scanning(tmp_path, capsys, content):
    bad = tmp_path / "bad.json"
    bad.write_text(content, encoding="utf-8")
    root = str(tmp_path / "r")
    write(root, "app.py", "x = 1\n")
    code = cli.main(["--no-update-check", "scan", root, "--offline", "--yes", "--plain", "--no-menu", "--baseline", str(bad)])
    assert code == 2 and "baseline" in capsys.readouterr().out.lower()


def test_baseline_loader_errors_name_the_problem(tmp_path):
    from secure_repo.core.scanner import load_baseline

    with pytest.raises(ValueError, match="Cannot read"):
        load_baseline(str(tmp_path / "missing.json"))
    bad = tmp_path / "bad.json"
    bad.write_text('{"findings": [{"id": "x"}]}', encoding="utf-8")
    with pytest.raises(ValueError, match="not a Secure Repo report"):
        load_baseline(str(bad))
    ok = tmp_path / "ok.json"
    ok.write_text('{"findings": [{"fingerprint": "abc"}, {"fingerprint": "def"}]}', encoding="utf-8")
    assert load_baseline(str(ok)) == {"abc", "def"}


# ---------------------------------------------------------------------- --since (C-49)
def git(root, *args):
    subprocess.run(["git", "-C", root, "-c", "user.name=t", "-c", "user.email=t@example.org", *args], check=True,
                   capture_output=True)


@pytest.fixture()
def git_repo(tmp_path):
    root = str(tmp_path / "gitrepo")
    write(root, "app/committed.py", VULNERABLE)
    write(root, "README.md", "hi\n")
    git(root, "init", "-q", "-b", "main")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "initial")
    return root


def test_since_analyzes_only_files_that_changed(git_repo):
    write(git_repo, "app/changed.py", VULNERABLE.replace("run", "run_changed"))        # untracked
    with open(os.path.join(git_repo, "README.md"), "a", encoding="utf-8") as handle:     # modified, but only docs
        handle.write("more\n")
    report, scanner = scan(git_repo, offline=True, since="HEAD")
    files = {f["file"] for f in report["findings"] if f["rule_id"] == "SR-PY-005"}
    assert files == {"app/changed.py"}
    since = report["analysis"]["not_analyzed"]["since"]
    assert since["ref"] == "HEAD" and since["changed"] == 2 and since["unchanged_skipped"] >= 1
    assert any("--since HEAD" in line for line in scanner.log_lines)


def test_since_a_clean_tree_analyzes_nothing_but_still_reports_hygiene(git_repo):
    report, _ = scan(git_repo, offline=True, since="HEAD")
    assert not [f for f in report["findings"] if f["rule_id"] == "SR-PY-005"]
    assert any(f["rule_id"] == "SR-HYG-001" for f in report["findings"])


def test_since_rejects_unknown_references_and_non_repositories(git_repo, tmp_path, capsys):
    with pytest.raises(Exception, match="Unknown Git reference"):
        scan(git_repo, offline=True, since="no-such-branch")
    with pytest.raises(Exception, match="Invalid Git reference"):
        scan(git_repo, offline=True, since="--output=/tmp/x")
    folder = str(tmp_path / "plain")
    write(folder, "app.py", VULNERABLE)
    with pytest.raises(Exception, match="local Git repository"):
        scan(folder, offline=True, since="HEAD")


def test_ref_validation():
    from secure_repo.core import gitops

    for good in ("origin/main", "HEAD~3", "v1.2.3", "a1b2c3d", "feature/x-y_z", "HEAD^"):
        assert gitops.validate_ref(good) == good
    for bad in ("", "-rf", "a..b", "a b", "x;y", "$(id)", "a\nb"):
        with pytest.raises(gitops.GitError):
            gitops.validate_ref(bad)


def test_cli_rejects_a_bad_ca_bundle_before_scanning(tmp_path, capsys):
    root = str(tmp_path / "r")
    write(root, "app.py", "x = 1\n")
    code = cli.main(["--no-update-check", "scan", root, "--offline", "--yes", "--plain", "--no-menu",
                     "--ca-bundle", str(tmp_path / "nope.pem")])
    assert code == 2 and "CA bundle not found" in capsys.readouterr().out
    netio.configure(ca_bundle="")
