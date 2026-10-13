"""Resolves a scan target (local repo, folder or remote URL + branch) into files on disk."""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass, field
from typing import List, Optional

from secure_repo.core import gitops
from secure_repo.core.events import EventBus


@dataclass
class Target:
    kind: str  # "remote" or "local"
    location: str
    branch: Optional[str] = None
    # Access token for private repositories - memory only, never serialized or printed.
    credentials: Optional[gitops.GitCredentials] = field(default=None, repr=False, compare=False)

    @classmethod
    def parse(cls, value: Optional[str], branch: Optional[str] = None) -> Target:
        value = (value or ".").strip()
        if gitops.is_git_url(value):
            clean, credentials = gitops.split_credentials(value)
            return cls("remote", clean, branch, credentials)
        return cls("local", os.path.abspath(os.path.expanduser(value)), branch)


@dataclass
class Workspace:
    path: str
    name: str
    target: Target
    branch: Optional[str]
    commit: str
    mode: str
    repo_root: Optional[str] = None
    remote: str = ""
    temp_dir: Optional[str] = None
    notes: List[str] = field(default_factory=list)

    def cleanup(self) -> None:
        if self.temp_dir:
            gitops.remove_tree(self.temp_dir)
            self.temp_dir = None


def discover_branches(target: Target, interactive: bool = False) -> List[gitops.Branch]:
    """List branches for a target; an empty list means 'not a git repository'."""
    if target.kind == "remote":
        return gitops.list_remote_branches(target.location, interactive=interactive, credentials=target.credentials)
    root = gitops.find_repo_root(target.location)
    if not root:
        return []
    return gitops.list_local_branches(root)


def prepare_workspace(target: Target, bus: EventBus, interactive: bool = False) -> Workspace:
    if target.kind == "remote":
        url = gitops.validate_url(target.location)
        temp_dir = tempfile.mkdtemp(prefix="securerepo-")
        dest = os.path.join(temp_dir, "repo")
        bus.log(f"Cloning {url} (branch: {target.branch or 'default'}, depth 1, hooks disabled)")
        try:
            commit = gitops.clone(url, target.branch, dest, interactive=interactive, credentials=target.credentials)
        except Exception:
            gitops.remove_tree(temp_dir)
            raise
        branch = target.branch or gitops.current_branch(dest) or "default"
        bus.log(f"Clone complete at commit {commit[:12]}", "ok")
        return Workspace(path=dest, name=gitops.repo_name_from_url(url), target=target, branch=branch,
                         commit=commit, mode="clone", repo_root=dest, remote=url, temp_dir=temp_dir)

    path = target.location
    if not os.path.isdir(path):
        raise FileNotFoundError(f"Directory not found: {path}")
    root = gitops.find_repo_root(path)
    if not root:
        bus.log("Target is not a Git repository - scanning the folder as-is", "warn")
        return Workspace(path=path, name=os.path.basename(os.path.normpath(path)) or path, target=target,
                         branch=None, commit="", mode="folder")

    current = gitops.current_branch(root)
    name = os.path.basename(os.path.normpath(root))
    remote = gitops.remote_url(root)
    if not target.branch or target.branch == current:
        commit = gitops.head_commit(root)
        bus.log(f"Scanning working tree of '{current or 'detached HEAD'}' (includes uncommitted changes)")
        workspace = Workspace(path=root, name=name, target=target, branch=current or "HEAD", commit=commit,
                              mode="working-tree", repo_root=root, remote=remote)
        workspace.notes.append("Working tree scan: uncommitted changes are included.")
        return workspace

    temp_dir = tempfile.mkdtemp(prefix="securerepo-")
    dest = os.path.join(temp_dir, "export")
    bus.log(f"Exporting branch '{target.branch}' with git archive (your working tree is not modified)")
    try:
        commit = gitops.export_ref(root, target.branch, dest)
    except Exception:
        gitops.remove_tree(temp_dir)
        raise
    bus.log(f"Branch exported at commit {commit[:12]}", "ok")
    return Workspace(path=dest, name=name, target=target, branch=target.branch, commit=commit,
                     mode="branch-export", repo_root=root, remote=remote, temp_dir=temp_dir)
