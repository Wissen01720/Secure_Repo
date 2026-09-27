"""Safe wrappers around the git command line (branch discovery, cloning, exporting)."""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import tarfile
from dataclasses import asdict, dataclass
from typing import Dict, List, Optional


class GitError(RuntimeError):
    pass


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


def validate_branch(branch: str) -> str:
    branch = branch.strip()
    if not branch or branch.startswith("-") or ".." in branch or any(c in branch for c in " ~^:?*[\\\r\n\t"):
        raise GitError(f"Invalid branch name: {branch!r}")
    return branch


def _run(args: List[str], cwd: Optional[str] = None, timeout: int = 120, interactive: bool = False) -> str:
    env = os.environ.copy()
    env["GIT_LFS_SKIP_SMUDGE"] = "1"
    env["GIT_TERMINAL_PROMPT"] = "1" if interactive else "0"
    if not interactive:
        env.setdefault("GIT_ASKPASS", "")
        env.setdefault("SSH_ASKPASS", "")
        env["GIT_SSH_COMMAND"] = env.get("GIT_SSH_COMMAND", "ssh -o BatchMode=yes")
    try:
        completed = subprocess.run(
            ["git"] + _SAFE_GIT_CONFIG + ([] if interactive else ["-c", "credential.interactive=never"]) + args,
            cwd=cwd, env=env, capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=timeout, stdin=None if interactive else subprocess.DEVNULL,
        )
    except FileNotFoundError as exc:
        raise GitError("git is not installed or not on PATH. Install it from https://git-scm.com") from exc
    except subprocess.TimeoutExpired as exc:
        raise GitError(f"git {args[0]} timed out after {timeout}s") from exc
    if completed.returncode != 0:
        message = (completed.stderr or completed.stdout).strip().splitlines()
        raise GitError(message[-1] if message else f"git {args[0]} failed")
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


def list_remote_branches(url: str, interactive: bool = False) -> List[Branch]:
    url = validate_url(url)
    output = _run(["ls-remote", "--symref", "--", url, "HEAD", "refs/heads/*"], timeout=90, interactive=interactive)
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


def clone(url: str, branch: Optional[str], dest: str, interactive: bool = False) -> str:
    url = validate_url(url)
    args = ["clone", "--depth", "1", "--single-branch", "--no-tags", "--quiet"]
    if branch:
        args += ["--branch", validate_branch(branch)]
    args += ["--", url, dest]
    _run(args, timeout=900, interactive=interactive)
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
