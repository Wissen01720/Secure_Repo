import os
import shutil
import subprocess

import pytest

from secure_repo.core import gitops, updater
from secure_repo.core.events import EventBus
from secure_repo.core.scanner import Scanner, ScanOptions
from secure_repo.core.workspace import Target

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
GIT_ENV = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.com",
               GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.com")


def git(cwd, *args):
    subprocess.run(["git", *args], cwd=cwd, env=GIT_ENV, check=True, capture_output=True)


def write(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(content)


# ---------------------------------------------------------------------- private repositories
def test_credentials_are_removed_from_urls_and_never_printed():
    clean, credentials = gitops.split_credentials("https://alice:s3cr3t-token@github.com/org/private.git")
    assert clean == "https://github.com/org/private.git"
    assert credentials.token == "s3cr3t-token" and credentials.username == "alice"
    assert "s3cr3t" not in repr(credentials) and "s3cr3t" not in str(credentials)
    target = Target.parse("https://alice:s3cr3t-token@github.com/org/private.git")
    assert target.location == clean and "s3cr3t" not in repr(target)


def test_token_is_injected_as_scoped_header_not_as_argument():
    env = {}
    extra = gitops.auth_config("https://gitlab.example.com:8443/team/app.git", gitops.GitCredentials("tok-123"), env)
    if gitops._env_config_supported():
        assert extra == []
        assert env["GIT_CONFIG_KEY_0"] == "http.https://gitlab.example.com:8443/.extraHeader"
        assert env["GIT_CONFIG_VALUE_0"].startswith("Authorization: Basic ")
        assert "tok-123" not in env["GIT_CONFIG_VALUE_0"]  # base64 encoded, never plain
    with pytest.raises(gitops.GitError):
        gitops.auth_config("git@github.com:org/app.git", gitops.GitCredentials("tok"), {})


def test_provider_defaults_and_error_classification():
    assert gitops.default_username("https://github.com/o/r") == "x-access-token"
    assert gitops.default_username("https://gitlab.com/o/r") == "oauth2"
    assert gitops.default_username("https://bitbucket.org/o/r") == "x-token-auth"
    assert gitops.default_username("https://dev.azure.com/o/p/_git/r") == "pat"
    private = "remote: Repository not found.\nfatal: repository 'https://github.com/o/p.git/' not found"
    assert gitops.AUTH_ERROR_RE.search(private)
    assert gitops.AUTH_ERROR_RE.search("fatal: unable to get password from user")
    assert not gitops.AUTH_ERROR_RE.search("fatal: Remote branch dev not found in upstream origin")
    secret = gitops.GitCredentials("tok-abc")
    assert "tok-abc" not in gitops._scrub("Authorization failed for tok-abc at https://u:tok-abc@host/x", secret)


def test_token_from_environment(monkeypatch):
    monkeypatch.delenv("SECURE_REPO_GIT_TOKEN", raising=False)
    monkeypatch.setenv("GH_TOKEN", "from-gh")
    assert gitops.credentials_from_env("https://github.com/o/r").token == "from-gh"
    assert gitops.credentials_from_env("https://gitlab.com/o/r") is None
    monkeypatch.setenv("SECURE_REPO_GIT_TOKEN", "explicit")
    assert gitops.credentials_from_env("https://gitlab.com/o/r").token == "explicit"


def test_a_private_repository_token_never_reaches_the_report():
    """Integration with the trust model: a remote (private) scan is untrusted and its token is never stored."""
    token = "tok-must-not-leak-9f3a"
    target = Target.parse(f"https://alice:{token}@github.com/org/private.git")
    target.credentials = gitops.GitCredentials(token)
    assert token not in repr(target) and token not in target.location
    scanner = Scanner(ScanOptions(offline=True), EventBus())
    with pytest.raises(gitops.GitError) as error:  # the repository does not exist: the failure must not echo the token
        scanner.run(target, write_reports=False)
    assert token not in str(error.value)
    assert all(token not in line for line in scanner.log_lines)


# ---------------------------------------------------------------------- updates
@pytest.fixture()
def release_setup(tmp_path):
    """A fake upstream (like GitHub) and a user installation cloned from it."""
    source = str(tmp_path / "source")
    write(os.path.join(source, "pyproject.toml"), "[project]\nname = 'secure-repo'\n")
    write(os.path.join(source, "secure_repo", "__init__.py"), '__version__ = "1.1.0"\n')
    write(os.path.join(source, "CHANGELOG.md"), "# Changelog\n\n## [1.1.0]\n\n- first\n")
    git(source, "init", "-q", "-b", "main")
    git(source, "add", "-A")
    git(source, "commit", "-qm", "1.1.0")
    upstream = str(tmp_path / "upstream.git")
    git(str(tmp_path), "clone", "-q", "--bare", source, upstream)
    install = str(tmp_path / "install")
    git(str(tmp_path), "clone", "-q", upstream, install)
    git(source, "remote", "add", "origin", upstream)
    return source, install


def publish(source, version, message):
    write(os.path.join(source, "secure_repo", "__init__.py"), f'__version__ = "{version}"\n')
    write(os.path.join(source, "CHANGELOG.md"), f"# Changelog\n\n## [{version}]\n\n- {message}\n\n## [1.1.0]\n\n- first\n")
    git(source, "commit", "-qam", message)
    git(source, "push", "-q", "origin", "main")


def test_every_published_commit_is_announced_and_installed_in_place(release_setup):
    source, install = release_setup
    assert updater.detect_install(install).mode == "git"
    assert updater.check(force=True, project_dir=install).available is False
    publish(source, "1.2.0", "Private repository tokens")
    info = updater.check(force=True, project_dir=install)
    assert info.available and info.commits_behind == 1 and info.latest_version == "1.2.0"
    assert info.changes[0].endswith("Private repository tokens") and "[1.2.0]" in info.notes
    result = updater.apply_update(info, project_dir=install)
    assert result.ok and result.restart_required and result.to_version == "1.2.0"
    with open(os.path.join(install, "secure_repo", "__init__.py"), encoding="utf-8") as handle:
        assert "1.2.0" in handle.read()
    notice = updater.pop_post_update_notice()
    assert notice["to"] == "1.2.0" and updater.pop_post_update_notice() is None
    assert updater.check(force=True, project_dir=install).available is False


def test_update_refuses_to_overwrite_local_changes(release_setup):
    source, install = release_setup
    publish(source, "1.2.0", "New release")
    write(os.path.join(install, "secure_repo", "__init__.py"), '__version__ = "1.1.0-local"\n')
    result = updater.apply_update(updater.check(force=True, project_dir=install), project_dir=install)
    assert not result.ok and "Local changes" in result.message


def test_changelog_and_version_helpers():
    text = "# Changelog\n\n## [1.2.0] - 2026-10-05\n\n- a\n\n## [1.1.0]\n\n- b\n"
    assert updater.changelog_section(text).startswith("## [1.2.0]")
    assert "- b" in updater.changelog_section(text, "1.1.0")
    assert updater.is_newer("1.10.0", "1.9.3") and not updater.is_newer("1.1.0", "1.1.0")
    assert updater.version_from_source('__version__ = "2.0.1"') == "2.0.1"
