"""The repository's own supply-chain hygiene: CI, Dependabot, lock file and launchers (C-37, C-39, C-43, C-44)."""
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as handle:
        return handle.read()


def test_every_action_is_pinned_to_a_full_commit_sha():
    workflow = read(".github", "workflows", "ci.yml")
    uses = re.findall(r"^\s*-?\s*uses:\s*(\S+)", workflow, re.MULTILINE)
    assert uses, "the workflow must use at least one action"
    for reference in uses:
        assert re.fullmatch(r"[\w./-]+@[0-9a-f]{40}", reference), f"{reference} is not pinned to a commit SHA"


def test_ci_covers_the_three_platforms_and_runs_lint_types_and_dogfood():
    workflow = read(".github", "workflows", "ci.yml")
    for needed in ("ubuntu-latest", "windows-latest", "macos-latest", "ruff check", "mypy secure_repo", "--fail-on high",
                   "upload-sarif", "--require-hashes", "persist-credentials: false"):
        assert needed in workflow, needed
    assert re.search(r"^permissions:\s*\n\s+contents: read", workflow, re.MULTILINE), "top-level permissions must be read-only"
    assert "pull_request_target" not in workflow


def test_dependabot_watches_python_and_actions():
    config = read(".github", "dependabot.yml")
    assert 'package-ecosystem: "pip"' in config and 'package-ecosystem: "github-actions"' in config
    assert config.count('interval: "weekly"') == 2


def test_lock_file_has_hashes_for_every_package_and_matches_pyproject():
    lock = read("requirements.lock")
    packages = re.findall(r"^([A-Za-z0-9_.-]+)==\S+", lock, re.MULTILINE)
    assert {"rich", "pygments", "markdown-it-py", "mdurl"} <= set(packages)
    blocks = re.split(r"\n(?=[A-Za-z0-9_.-]+==)", lock)
    for block in blocks:
        if re.match(r"[A-Za-z0-9_.-]+==", block):
            assert "--hash=sha256:" in block, block.splitlines()[0]
    pyproject = read("pyproject.toml")
    for declared in re.findall(r'"([A-Za-z0-9_.-]+)(?:\[[^\]]*\])?[<>=!~]', pyproject.split("dependencies = [", 1)[1].split("]", 1)[0]):
        assert declared.lower() in {p.lower() for p in packages}, declared
    assert not os.path.exists(os.path.join(ROOT, "requirements.txt")), "one source of truth for dependencies"


def test_launchers_trust_the_environment_only_after_a_successful_install():
    shell, batch = read("run.sh"), read("run.bat")
    assert ".installed" in shell and ".installed" in batch
    assert shell.index("pip install") < shell.index('echo "installed" > "$VENV/.installed"')
    assert batch.index("pip install") < batch.index('echo installed> "%VENV%\\.installed"')
    assert batch.count("if errorlevel 1 goto :failed") >= 2
    assert "--require-hashes" in shell and "--require-hashes" in batch
    assert "--upgrade pip" not in shell and "--upgrade pip" not in batch


def test_updater_refreshes_dependencies_from_the_hashed_lock():
    source = read("secure_repo", "core", "updater.py")
    assert "requirements.lock" in source and "--require-hashes" in source and "requirements.txt" not in source


def test_ci_measures_accuracy_on_pinned_third_party_repositories():
    workflow = read(".github", "workflows", "ci.yml")
    assert "benchmark --external --fetch" in workflow and "--min-precision" in workflow and "--min-recall" in workflow
    assert "SECURE_REPO_ONLINE_TESTS" in workflow
