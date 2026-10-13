"""Safe wrappers around the git command line (branch discovery, cloning, exporting)."""

from __future__ import annotations

import base64
import os
import re
import shutil
import stat
import subprocess
import tarfile
from dataclasses import asdict, dataclass
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlsplit, urlunsplit


class GitError(RuntimeError):
    pass


class GitAuthError(GitError):
    """The remote rejected the request because credentials are missing or invalid."""

    def __init__(self, message: str, sso: bool = False):
        super().__init__(message)
        self.sso = sso


class GitCredentials:
    """Access token (and optional username) for private HTTPS repositories.

    The token is never placed in a URL, in process arguments, in reports or in logs: it is handed to Git as an
    ``Authorization`` header scoped to the repository host through ``GIT_CONFIG_*`` environment variables, and it
    only lives in memory for the current session.
    """

    __slots__ = ("token", "username")

    def __init__(self, token: str, username: str = ""):
        self.token = (token or "").strip()
        self.username = (username or "").strip()

    def __repr__(self) -> str:  # never print the secret
        return "GitCredentials(token=****)"

    __str__ = __repr__

    def __bool__(self) -> bool:
        return bool(self.token)


AUTH_ERROR_RE = re.compile(
    r"(?i)authentication failed|could not read (?:username|password)|terminal prompts disabled|"
    r"unable to get (?:password|username)|logon failed|credential|"
    r"repository ['\"]?[^\n]*['\"]? not found|repository not found|invalid username or password|access denied|"
    r"requested url returned error: 40[134]|http basic: access denied|permission denied \(publickey|"
    r"bad credentials|not authorized|authorization failed")
SSO_ERROR_RE = re.compile(r"(?i)saml|single sign-on|\bsso\b")
TOKEN_ENV = {
    "github": ("GH_TOKEN", "GITHUB_TOKEN"),
    "gitlab": ("GITLAB_TOKEN", "CI_JOB_TOKEN"),
    "bitbucket": ("BITBUCKET_TOKEN",),
    "azure": ("AZURE_DEVOPS_PAT", "AZURE_DEVOPS_EXT_PAT", "SYSTEM_ACCESSTOKEN"),
}


@dataclass
class Branch:
    name: str
    commit: str = ""
    date: str = ""
    remote: bool = False
    current: bool = False
    default: bool = False

    def to_dict(self) -> Dict:
        return asdict(self)


_URL_RE = re.compile(r"^(?:(?:https?|ssh|git)://[^\s]+|[\w.\-]+@[\w.\-]+:[^\s]+)$")
_SAFE_GIT_CONFIG = [
    "-c", "protocol.ext.allow=never",  # never allow the ext:: transport (command execution)
    "-c", "protocol.file.allow=user",
    "-c", "core.hooksPath=" + os.devnull,  # never run repository hooks
    "-c", "core.fsmonitor=false",
]


def git_available() -> bool:
    return shutil.which("git") is not None


def git_version() -> str:
    try:
        return _run(["--version"]).strip().replace("git version ", "")
    except GitError:
        return "not found"


def is_git_url(value: str) -> bool:
    return bool(_URL_RE.match(value.strip())) and not value.strip().startswith("-")


def validate_url(url: str) -> str:
    url = url.strip()
    if not url or url.startswith("-") or any(ch in url for ch in "\r\n\t "):
        raise GitError("Invalid repository URL.")
    if url.lower().startswith(("ext::", "file://", "fd::")):
        raise GitError("This transport is not allowed. Use https://, ssh:// or git@host:path URLs.")
    if not is_git_url(url):
        raise GitError("Unsupported repository URL. Use https://, ssh://, git:// or git@host:owner/repo.git")
    return url


def host_of(url: str) -> str:
    if "://" in url:
        return (urlsplit(url).hostname or "").lower()
    match = re.match(r"^[\w.\-]+@([\w.\-]+):", url)
    return match.group(1).lower() if match else ""


def provider_of(url: str) -> str:
    host = host_of(url)
    if "github" in host:
        return "github"
    if "gitlab" in host:
        return "gitlab"
    if "bitbucket" in host:
        return "bitbucket"
    if "dev.azure.com" in host or "visualstudio.com" in host:
        return "azure"
    return "generic"


def is_https(url: str) -> bool:
    return url.lower().startswith(("https://", "http://"))


def default_username(url: str) -> str:
    """Username Git hosts expect when a personal access token is used as the password."""
    return {"github": "x-access-token", "gitlab": "oauth2", "bitbucket": "x-token-auth",
            "azure": "pat"}.get(provider_of(url), "git")


def split_credentials(url: str) -> Tuple[str, Optional[GitCredentials]]:
    """Remove ``user:token@`` from an https URL so the secret never reaches reports or logs."""
    url = url.strip()
    if not is_https(url):
        return url, None
    parts = urlsplit(url)
    if parts.password is None:
        return url, None
    netloc = parts.hostname or ""
    if parts.port:
        netloc += f":{parts.port}"
    clean = urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))
    return clean, GitCredentials(parts.password, parts.username or "")


def credentials_from_env(url: str) -> Optional[GitCredentials]:
    """SECURE_REPO_GIT_TOKEN (any host) or the usual CI variable of the provider."""
    token = os.environ.get("SECURE_REPO_GIT_TOKEN", "")
    if token:
        return GitCredentials(token, os.environ.get("SECURE_REPO_GIT_USERNAME", ""))
    for name in TOKEN_ENV.get(provider_of(url), ()):
        if os.environ.get(name):
            return GitCredentials(os.environ[name], "gitlab-ci-token" if name == "CI_JOB_TOKEN" else "")
    return None


def _env_config_supported() -> bool:
    match = re.search(r"(\d+)\.(\d+)", git_version())
    return bool(match) and (int(match.group(1)), int(match.group(2))) >= (2, 31)


def auth_config(url: str, credentials: Optional[GitCredentials], env: Dict[str, str]) -> List[str]:
    """Inject an Authorization header scoped to the repository host. Returns extra ``-c`` args (old Git only)."""
    if not credentials:
        return []
    if not is_https(url):
        raise GitError("Access tokens only work with https:// URLs. For SSH URLs configure an SSH key "
                       "(ssh-agent) with access to the repository.")
    parts = urlsplit(url)
    prefix = f"{parts.scheme}://{parts.hostname}" + (f":{parts.port}" if parts.port else "") + "/"
    user = credentials.username or default_username(url)
    basic = base64.b64encode(f"{user}:{credentials.token}".encode()).decode("ascii")
    key, value = f"http.{prefix}.extraHeader", f"Authorization: Basic {basic}"
    if _env_config_supported():
        index = int(env.get("GIT_CONFIG_COUNT", "0") or 0)
        env[f"GIT_CONFIG_KEY_{index}"] = key
        env[f"GIT_CONFIG_VALUE_{index}"] = value
        env["GIT_CONFIG_COUNT"] = str(index + 1)
        return []
    return ["-c", f"{key}={value}"]  # Git < 2.31 has no GIT_CONFIG_COUNT


def _scrub(message: str, credentials: Optional[GitCredentials] = None) -> str:
    if credentials and credentials.token:
        message = message.replace(credentials.token, "****")
        for candidate in {credentials.username, "x-access-token", "oauth2", "x-token-auth", "pat", "git"}:
            raw = f"{candidate}:{credentials.token}".encode()
            message = message.replace(base64.b64encode(raw).decode("ascii"), "****")
    return re.sub(r"(https?://)[^/\s:@]+:[^/\s@]+@", r"\1****@", message)


def auth_help(url: str, sso: bool = False) -> str:
    provider = provider_of(url)
    scopes = {
        "github": "a fine-grained token with 'Contents: Read' on the repository (or a classic token with 'repo')",
        "gitlab": "a personal/project access token with 'read_repository'",
        "bitbucket": "a repository access token with 'Repositories: Read'",
        "azure": "a personal access token with 'Code (Read)'",
    }.get(provider, "a personal access token with read access to the repository")
    text = f"This repository requires authentication (private or organization repository). Create {scopes}."
    if sso or provider == "github":
        text += (" If the organization enforces SAML single sign-on, authorize the token for that organization "
                 "(GitHub > Settings > Developer settings > Tokens > Configure SSO).")
    return text


def validate_branch(branch: str) -> str:
    branch = branch.strip()
    if not branch or branch.startswith("-") or ".." in branch or any(c in branch for c in " ~^:?*[\\\r\n\t"):
        raise GitError(f"Invalid branch name: {branch!r}")
    return branch


def _run(args: List[str], cwd: Optional[str] = None, timeout: int = 120, interactive: bool = False,
         url: Optional[str] = None, credentials: Optional[GitCredentials] = None) -> str:
    env = os.environ.copy()
    env["GIT_LFS_SKIP_SMUDGE"] = "1"
    env["GIT_TERMINAL_PROMPT"] = "1" if interactive else "0"
    if not interactive:
        env.setdefault("GIT_ASKPASS", "")
        env.setdefault("SSH_ASKPASS", "")
        env["GIT_SSH_COMMAND"] = env.get("GIT_SSH_COMMAND", "ssh -o BatchMode=yes")
    extra = auth_config(url, credentials, env) if (url and credentials) else []
    try:
        completed = subprocess.run(
            ["git"] + _SAFE_GIT_CONFIG + extra + ([] if interactive else ["-c", "credential.interactive=never"]) + args,
            cwd=cwd, env=env, capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=timeout, stdin=None if interactive else subprocess.DEVNULL,
        )
    except FileNotFoundError as exc:
        raise GitError("git is not installed or not on PATH. Install it from https://git-scm.com") from exc
    except subprocess.TimeoutExpired as exc:
        raise GitError(f"git {args[0]} timed out after {timeout}s") from exc
    if completed.returncode != 0:
        output = _scrub((completed.stderr or completed.stdout).strip(), credentials)
        lines = output.splitlines()
        if url and AUTH_ERROR_RE.search(output):
            sso = bool(SSO_ERROR_RE.search(output))
            reason = "the access token was rejected" if credentials else "no valid credentials were provided"
            raise GitAuthError(f"Authentication required for {host_of(url) or 'the remote'}: {reason}. "
                               f"{auth_help(url, sso)}", sso=sso)
        raise GitError(lines[-1] if lines else f"git {args[0]} failed")
    return completed.stdout


def find_repo_root(path: str) -> Optional[str]:
    if not git_available() or not os.path.isdir(path):
        return None
    try:
        root = _run(["-C", path, "rev-parse", "--show-toplevel"], timeout=20).strip()
    except GitError:
        return None
    return os.path.normpath(root) if root else None


def current_branch(root: str) -> Optional[str]:
    try:
        name = _run(["-C", root, "rev-parse", "--abbrev-ref", "HEAD"], timeout=20).strip()
    except GitError:
        return None
    return None if name == "HEAD" else name


def head_commit(root: str, ref: str = "HEAD") -> str:
    try:
        return _run(["-C", root, "rev-parse", "--verify", "--quiet", ref + "^{commit}"], timeout=20).strip()
    except GitError:
        return ""


def remote_url(root: str) -> str:
    try:
        return _run(["-C", root, "remote", "get-url", "origin"], timeout=20).strip()
    except GitError:
        return ""


def list_local_branches(root: str) -> List[Branch]:
    output = _run([
        "-C", root, "for-each-ref",
        "--format=%(refname)%09%(objectname:short)%09%(committerdate:short)",
        "refs/heads", "refs/remotes",
    ], timeout=30)
    current = current_branch(root)
    branches: List[Branch] = []
    local_names = set()
    for line in output.splitlines():
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        ref, commit, date = parts
        if ref.startswith("refs/heads/"):
            name = ref[len("refs/heads/"):]
            local_names.add(name)
            branches.append(Branch(name=name, commit=commit, date=date, current=(name == current)))
        elif ref.startswith("refs/remotes/"):
            name = ref[len("refs/remotes/"):]
            if name.endswith("/HEAD") or "/" not in name:
                continue
            branches.append(Branch(name=name, commit=commit, date=date, remote=True))
    # Hide remote-tracking duplicates of local branches that point to the same commit.
    by_name = {b.name: b for b in branches if not b.remote}
    filtered = []
    for branch in branches:
        if branch.remote:
            short = branch.name.split("/", 1)[1]
            local = by_name.get(short)
            if local and local.commit == branch.commit:
                continue
        filtered.append(branch)
    filtered.sort(key=lambda b: (not b.current, b.remote, b.name.lower()))
    return filtered


def list_remote_branches(url: str, interactive: bool = False,
                         credentials: Optional[GitCredentials] = None) -> List[Branch]:
    url = validate_url(url)
    output = _run(["ls-remote", "--symref", "--", url, "HEAD", "refs/heads/*"], timeout=90, interactive=interactive,
                  url=url, credentials=credentials or credentials_from_env(url))
    default = None
    branches: List[Branch] = []
    for line in output.splitlines():
        if line.startswith("ref:"):
            target = line.split()[1]
            if target.startswith("refs/heads/"):
                default = target[len("refs/heads/"):]
            continue
        parts = line.split("\t")
        if len(parts) == 2 and parts[1].startswith("refs/heads/"):
            branches.append(Branch(name=parts[1][len("refs/heads/"):], commit=parts[0][:7], remote=True))
    for branch in branches:
        branch.default = branch.name == default
    branches.sort(key=lambda b: (not b.default, b.name.lower()))
    return branches


def clone(url: str, branch: Optional[str], dest: str, interactive: bool = False,
          credentials: Optional[GitCredentials] = None) -> str:
    url = validate_url(url)
    args = ["clone", "--depth", "1", "--single-branch", "--no-tags", "--quiet"]
    if branch:
        args += ["--branch", validate_branch(branch)]
    args += ["--", url, dest]
    _run(args, timeout=900, interactive=interactive, url=url, credentials=credentials or credentials_from_env(url))
    return head_commit(dest)


def export_ref(root: str, ref: str, dest: str) -> str:
    """Extract the tree of ``ref`` into ``dest`` without touching the working tree."""
    ref = validate_branch(ref)
    commit = head_commit(root, ref)
    if not commit:
        raise GitError(f"Branch or reference not found: {ref}")
    os.makedirs(dest, exist_ok=True)
    env = os.environ.copy()
    env["GIT_LFS_SKIP_SMUDGE"] = "1"
    process = subprocess.Popen(
        ["git"] + _SAFE_GIT_CONFIG + ["-C", root, "archive", "--format=tar", commit],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL, env=env,
    )
    try:
        with tarfile.open(fileobj=process.stdout, mode="r|") as archive:
            if hasattr(tarfile, "data_filter"):
                archive.extractall(dest, filter="data")
            else:  # pragma: no cover - old Python fallback
                for member in archive:
                    target = os.path.realpath(os.path.join(dest, member.name))
                    if not target.startswith(os.path.realpath(dest) + os.sep) or member.issym() or member.islnk():
                        continue
                    archive.extract(member, dest)
    finally:
        _, stderr = process.communicate()
    if process.returncode not in (0, None):
        raise GitError(stderr.decode("utf-8", "replace").strip() or "git archive failed")
    return commit


def repo_name_from_url(url: str) -> str:
    name = url.rstrip("/").rsplit("/", 1)[-1].rsplit(":", 1)[-1]
    return name[:-4] if name.endswith(".git") else name or "repository"


def remove_tree(path: str) -> None:
    """rmtree that also works with read-only git objects on Windows."""

    def _on_error(func, target, _exc):
        try:
            os.chmod(target, stat.S_IWRITE)
            func(target)
        except OSError:
            pass

    if os.path.isdir(path):
        try:
            shutil.rmtree(path, onexc=_on_error)  # Python 3.12+
        except TypeError:
            shutil.rmtree(path, onerror=_on_error)
