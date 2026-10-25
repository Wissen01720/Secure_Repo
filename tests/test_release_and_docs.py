"""Release hygiene (C-45..C-57): documentation links, versions, metadata, themes and cautious compliance wording."""
import os
import re
import subprocess
import sys

import pytest

from secure_repo import __version__
from secure_repo.cli import main as cli
from secure_repo.core.models import OWASP_2025, OWASP_TOP10, owasp_2025_label
from tests.conftest import write

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOCS = [os.path.join(ROOT, "README.md"), os.path.join(ROOT, "README.es.md")] + [
    os.path.join(ROOT, "docs", name) for name in sorted(os.listdir(os.path.join(ROOT, "docs"))) if name.endswith(".md")]


def read(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as handle:
        return handle.read()


def github_slug(heading):
    text = heading.strip().lower()
    text = re.sub(r"[^\w\- ]", "", text)
    return text.replace(" ", "-")


def anchors_of(path):
    with open(path, encoding="utf-8") as handle:
        return {github_slug(m.group(1)) for m in re.finditer(r"^#{1,6} (.+)$", handle.read(), re.M)}


@pytest.mark.parametrize("path", DOCS, ids=lambda p: os.path.relpath(p, ROOT))
def test_every_relative_link_and_image_resolves(path):
    text = open(path, encoding="utf-8").read()
    problems = []
    for target in re.findall(r"\]\(([^)\s]+)\)|<img src=\"([^\"]+)\"", text):
        link = target[0] or target[1]
        if re.match(r"(https?:|mailto:)", link):
            continue
        file_part, _, anchor = link.partition("#")
        resolved = path if not file_part else os.path.normpath(os.path.join(os.path.dirname(path), file_part))
        if not os.path.exists(resolved):
            problems.append(f"{link}: no such file")
        elif anchor and resolved.endswith(".md") and anchor not in anchors_of(resolved):
            problems.append(f"{link}: no such heading")
    assert not problems, problems


def test_readme_is_short_and_points_to_the_documents():
    readme = read("README.md")
    assert len(readme.splitlines()) < 160
    for name in ("installation", "cli-guide", "analysis", "reference", "gui", "security-model", "troubleshooting",
                 "development", "releasing"):
        assert f"docs/{name}.md" in readme
    assert "README.es.md" in readme and "Inicio rápido" in read("README.es.md")


def test_versions_agree_and_the_changelog_has_the_release():
    assert re.search(rf'^version = "{re.escape(__version__)}"', read("pyproject.toml"), re.M)
    assert f"## [{__version__}]" in read("CHANGELOG.md")


def test_release_notes_come_from_the_changelog():
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import release_notes

    notes = release_notes.section(__version__, os.path.join(ROOT, "CHANGELOG.md"))
    assert notes.strip() and not notes.startswith("## ")
    with pytest.raises(SystemExit):
        release_notes.section("0.0.1", os.path.join(ROOT, "CHANGELOG.md"))
    completed = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "release_notes.py"), f"v{__version__}"],
                               capture_output=True, text=True, encoding="utf-8")
    assert completed.returncode == 0 and completed.stdout.strip() == notes.strip()


def test_package_metadata_is_modern_and_there_is_one_command():
    pyproject = read("pyproject.toml")
    assert 'requires-python = ">=3.11"' in pyproject
    assert 'license = "LicenseRef-SecureRepo-Ethical-Source-Available"' in pyproject and 'license-files = ["LICENSE"]' in pyproject
    assert "License ::" not in pyproject and "setuptools>=77" in pyproject
    scripts = pyproject.split("[project.scripts]")[1].split("[", 1)[0]
    assert "secure-repo =" in scripts and "securerepo" not in scripts


def test_publishing_workflow_uses_trusted_publishing_and_checks_the_tag():
    workflow = read(".github", "workflows", "publish.yml")
    assert "release:" in workflow and "published" in workflow
    assert workflow.count("id-token: write") == 1 and "environment:" in workflow and "name: pypi" in workflow
    assert "password:" not in workflow and "PYPI_TOKEN" not in workflow and "secrets." not in workflow
    assert "tag_name" in workflow and "twine check" in workflow
    for reference in re.findall(r"uses:\s*(\S+)", workflow):
        assert re.fullmatch(r"[\w./-]+@[0-9a-f]{40}", reference), reference


# ------------------------------------------------------------------ OWASP 2025 and compliance wording (C-53)
def test_every_2021_category_has_a_2025_equivalent():
    assert set(OWASP_2025) == set(OWASP_TOP10) - {"OTHER"}
    assert owasp_2025_label("A03") == "A05:2025 Injection"
    assert owasp_2025_label("A10") == "A01:2025 Broken Access Control"        # SSRF became part of broken access control
    assert owasp_2025_label("A06") == "A03:2025 Software Supply Chain Failures"
    assert owasp_2025_label("OTHER") == ""


def test_reports_show_both_owasp_editions_and_cautious_compliance_wording(tmp_path):
    from secure_repo.core.events import EventBus
    from secure_repo.core.scanner import Scanner, ScanOptions
    from secure_repo.core.workspace import Target

    root = str(tmp_path / "r")
    write(root, "app.py", "import os\nfrom flask import request\nos.system(request.args.get('c'))\n")
    report, folder = Scanner(ScanOptions(offline=True, trust_repo_config=True, compliance=True,
                                         output_dir=str(tmp_path / "out")), EventBus()).run(Target.parse(root))
    assert report["owasp_2025"]["A03"]["code"] == "A05"
    critical = open(os.path.join(folder, "findings", "critical.md"), encoding="utf-8").read()
    assert "A03:2021" in critical and "A05:2025 Injection" in critical
    evidence = open(os.path.join(folder, "compliance", "owasp.md"), encoding="utf-8").read()
    assert "NO ISSUE FOUND" in evidence and "✅ PASS" not in evidence and "not a compliance percentage" in evidence
    assert "does not show that the control is satisfied" in report["compliance"]["disclaimer"]


# ------------------------------------------------------------------ plain theme (C-57)
def run(argv, capsys):
    code = cli.main(["--no-update-check"] + argv)
    return code, re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", capsys.readouterr().out)


@pytest.fixture()
def reset_theme():
    from secure_repo.cli import theme

    yield
    theme.set_theme("hacker")


def test_plain_theme_removes_the_staging(tmp_path, capsys, reset_theme):
    root = str(tmp_path / "r")
    write(root, "app.py", "print('hi')\n")
    args = ["scan", root, "--offline", "--yes", "--no-menu", "-o", str(tmp_path / "out")]
    code, plain = run(["--theme", "plain"] + args, capsys)
    assert code == 0
    assert "Secure Repo " in plain and "⟦" not in plain and "SECURE//REPO" not in plain
    assert "Scan Report" in plain and "MISSION REPORT" not in plain and "Report Files" in plain
    from secure_repo.cli import theme

    theme.set_theme("hacker")
    code, loud = run(args, capsys)
    assert "MISSION REPORT" in loud and "⟦" in loud


def test_the_theme_can_come_from_the_environment(tmp_path, capsys, monkeypatch, reset_theme):
    monkeypatch.setenv("SECURE_REPO_THEME", "plain")
    root = str(tmp_path / "r")
    write(root, "app.py", "print('hi')\n")
    code, out = run(["scan", root, "--offline", "--yes", "--no-menu", "-o", str(tmp_path / "out")], capsys)
    assert code == 0 and "⟦" not in out


def test_the_gui_scripts_are_the_split_modules():
    index = read("secure_repo", "gui", "static", "index.html")
    scripts = re.findall(r'<script src="/static/([\w.-]+)"', index)
    assert scripts[:3] == ["core.js", "neural.js", "boxmap.js"] and scripts[3] == "app-state.js"
    assert scripts[-1] == "app-main.js" and "app.js" not in scripts
    for name in scripts:
        assert os.path.exists(os.path.join(ROOT, "secure_repo", "gui", "static", name)), name
        if name.startswith("app-"):
            assert len(read("secure_repo", "gui", "static", name).splitlines()) < 400, name


# ------------------------------------------------------------------ findings Secure Repo raised on itself
def test_hash_pinned_lock_file_with_continuations_counts_as_a_lock(tmp_path):
    from secure_repo.core import deps

    cont = " " + chr(92) + chr(10)
    text = ("rich==15.0.0" + cont + "    --hash=sha256:" + "a" * 64 + chr(10) + "    # via secure-repo" + chr(10)
            + "tomli==2.5.0 ; python_version < '3.11'" + cont + "    --hash=sha256:" + "b" * 64 + chr(10))
    parsed = deps.parse_requirements(text, "requirements.lock", [])
    assert [(d.name, d.version) for d in parsed] == [("rich", "15.0.0"), ("tomli", "2.5.0")]
    assert deps.parser_for("requirements.lock")[0] is deps.parse_requirements


def test_the_gui_keeps_its_session_token_out_of_web_storage():
    core = read("secure_repo", "gui", "static", "core.js")
    assert "sessionStorage" not in core and "localStorage" not in core
