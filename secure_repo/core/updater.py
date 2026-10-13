"""Self-update: detect new versions of Secure Repo and install them without re-cloning.

Two installation modes are supported:

* **git** - Secure Repo runs from a clone (launchers / ``pip install -e``). Updates are detected by fetching the
  tracked branch, so *every* published commit is announced. Installing = fast-forward ``git merge`` + dependency
  refresh when ``pyproject.toml``/``requirements.lock`` changed. Local edits are never overwritten.
* **pip** - installed as a package. Updates are detected through the GitHub API of the upstream repository and
  installed with ``pip install --upgrade`` pinned to the exact upstream commit.

Checks are cached (6 hours), run in the background, time out quickly and never block the tool.
Set ``SECURE_REPO_NO_UPDATE_CHECK=1`` to disable them.
"""

from __future__ import annotations

import json
import os
import re
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from typing import Callable, Dict, List, Optional

from secure_repo import __version__
from secure_repo.core import gitops, versions
from secure_repo.core.triage import data_dir

UPSTREAM = os.environ.get("SECURE_REPO_UPSTREAM", "Wissen01720/Secure_Repo")
UPSTREAM_BRANCH = os.environ.get("SECURE_REPO_UPSTREAM_BRANCH", "main")
CACHE_TTL = 6 * 3600
PACKAGE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROJECT_DIR = os.path.dirname(PACKAGE_DIR)
_VERSION_RE = re.compile(r'__version__\s*=\s*["\']([^"\']+)["\']')


@dataclass
class InstallInfo:
    mode: str                     # "git" or "pip"
    root: Optional[str] = None    # clone root (git mode)
    branch: Optional[str] = None
    remote: str = ""


@dataclass
class UpdateInfo:
    available: bool = False
    current_version: str = __version__
    latest_version: str = ""
    current_commit: str = ""
    latest_commit: str = ""
    commits_behind: int = 0
    changes: List[str] = field(default_factory=list)
    notes: str = ""
    mode: str = ""
    source: str = ""
    checked_at: float = 0.0
    error: str = ""

    def to_dict(self) -> Dict:
        return asdict(self)

    @property
    def summary(self) -> str:
        if not self.available:
            return f"Secure Repo {self.current_version} is up to date"
        target = self.latest_version or "new version"
        detail = f"{self.commits_behind} new change(s)" if self.commits_behind else "new release"
        return f"Update available: {self.current_version} -> {target} ({detail})"


@dataclass
class UpdateResult:
    ok: bool
    message: str
    restart_required: bool = False
    deferred: bool = False
    from_version: str = __version__
    to_version: str = ""
    log: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return asdict(self)


# ---------------------------------------------------------------------- state
def _state_path() -> str:
    return os.path.join(data_dir(), "update.json")


def load_state() -> Dict:
    try:
        with open(_state_path(), encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_state(data: Dict) -> None:
    path = _state_path()
    temp = path + ".tmp"
    with open(temp, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)
    os.replace(temp, path)


def checks_disabled() -> bool:
    return bool(os.environ.get("SECURE_REPO_NO_UPDATE_CHECK")) or bool(os.environ.get("CI"))


# ---------------------------------------------------------------------- detection
def detect_install(project_dir: str = PROJECT_DIR) -> InstallInfo:
    root = gitops.find_repo_root(project_dir)
    if root and os.path.normcase(os.path.realpath(root)) == os.path.normcase(os.path.realpath(project_dir)) \
            and os.path.isfile(os.path.join(root, "pyproject.toml")) \
            and os.path.isdir(os.path.join(root, "secure_repo")):
        return InstallInfo("git", root, gitops.current_branch(root), gitops._scrub(gitops.remote_url(root)))
    return InstallInfo("pip", remote=f"https://github.com/{UPSTREAM}")


def _git(root: str, *args: str, timeout: int = 60) -> str:
    return gitops._run(["-C", root] + list(args), timeout=timeout)


def version_from_source(text: str) -> str:
    match = _VERSION_RE.search(text or "")
    return match.group(1) if match else ""


def changelog_section(text: str, version: str = "") -> str:
    """Return the newest section of a Keep-a-Changelog style file (or the one for ``version``)."""
    sections = re.split(r"(?m)^## ", text or "")
    for section in sections[1:]:
        header = section.splitlines()[0] if section else ""
        if not version or version in header:
            return ("## " + section).strip()[:4000]
    return ""


def is_newer(latest: str, current: str) -> bool:
    a, b = versions.parse(latest), versions.parse(current)
    return bool(a and b and a > b)


def _check_git(install: InstallInfo) -> UpdateInfo:
    info = UpdateInfo(mode="git", source=install.remote, checked_at=time.time())
    root, branch = install.root, install.branch
    info.current_commit = gitops.head_commit(root)
    current_source = ""
    try:
        with open(os.path.join(root, "secure_repo", "__init__.py"), encoding="utf-8") as handle:
            current_source = handle.read()
    except OSError:
        pass
    info.current_version = version_from_source(current_source) or __version__
    if not branch:
        info.error = "detached HEAD - check out a branch to receive updates"
        return info
    _git(root, "fetch", "--quiet", "--no-tags", "origin", branch, timeout=30)
    info.latest_commit = _git(root, "rev-parse", "FETCH_HEAD").strip()
    info.commits_behind = int(_git(root, "rev-list", "--count", "HEAD..FETCH_HEAD").strip() or 0)
    info.available = info.commits_behind > 0
    if info.available:
        log = _git(root, "log", "--no-merges", "--format=%h %s", "-n", "25", "HEAD..FETCH_HEAD")
        info.changes = [line for line in log.splitlines() if line.strip()]
        try:
            info.latest_version = version_from_source(_git(root, "show", "FETCH_HEAD:secure_repo/__init__.py"))
        except gitops.GitError:
            info.latest_version = ""
        try:
            info.notes = changelog_section(_git(root, "show", "FETCH_HEAD:CHANGELOG.md"))
        except gitops.GitError:
            info.notes = ""
    else:
        info.latest_version = info.current_version
    return info


def _http(url: str, accept: str = "application/vnd.github+json", timeout: int = 6) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": f"secure-repo/{__version__}", "Accept": accept})
    with urllib.request.urlopen(request, timeout=timeout, context=ssl.create_default_context()) as response:  # nosec - fixed https URL
        return response.read(2_000_000).decode("utf-8", "replace")


def _check_pip(install: InstallInfo) -> UpdateInfo:
    info = UpdateInfo(mode="pip", source=install.remote, checked_at=time.time())
    state = load_state()
    info.current_commit = state.get("installed_commit", "")
    api = f"https://api.github.com/repos/{UPSTREAM}"
    info.latest_commit = _http(f"{api}/commits/{UPSTREAM_BRANCH}", "application/vnd.github.sha").strip()
    raw = f"https://raw.githubusercontent.com/{UPSTREAM}/{info.latest_commit}"
    info.latest_version = version_from_source(_http(f"{raw}/secure_repo/__init__.py", "text/plain"))
    try:
        info.notes = changelog_section(_http(f"{raw}/CHANGELOG.md", "text/plain"))
    except (urllib.error.URLError, OSError):
        info.notes = ""
    if info.current_commit:
        info.available = info.current_commit != info.latest_commit
        if info.available:
            try:
                compare = json.loads(_http(f"{api}/compare/{info.current_commit}...{info.latest_commit}"))
                commits = compare.get("commits", [])
                info.commits_behind = int(compare.get("ahead_by", len(commits)))
                info.changes = [f"{c['sha'][:7]} {c['commit']['message'].splitlines()[0]}" for c in commits][-25:][::-1]
            except (urllib.error.URLError, OSError, ValueError, KeyError):
                pass
    else:
        info.available = is_newer(info.latest_version, __version__)
    return info


def check(force: bool = False, project_dir: str = PROJECT_DIR) -> UpdateInfo:
    """Check for updates (cached for CACHE_TTL seconds unless ``force``)."""
    state = load_state()
    cached = state.get("last_check") or {}
    install = detect_install(project_dir)
    if not force and cached and time.time() - cached.get("checked_at", 0) < CACHE_TTL \
            and cached.get("mode") == install.mode and cached.get("current_version") == __version__ \
            and (install.mode != "git" or cached.get("current_commit") == gitops.head_commit(install.root)):
        return UpdateInfo(**{k: v for k, v in cached.items() if k in UpdateInfo.__dataclass_fields__})
    try:
        info = _check_git(install) if install.mode == "git" else _check_pip(install)
    except (gitops.GitError, urllib.error.URLError, OSError, ValueError) as exc:
        return UpdateInfo(mode=install.mode, source=install.remote, checked_at=time.time(),
                          error=gitops._scrub(str(getattr(exc, "reason", exc))))  # failures are not cached
    state["last_check"] = info.to_dict()
    save_state(state)
    return info


# ---------------------------------------------------------------------- background check
_background: Dict[str, object] = {}


def start_background_check(force: bool = False) -> None:
    if checks_disabled() or "thread" in _background:
        return

    def worker() -> None:
        try:
            _background["info"] = check(force=force)
        except Exception as exc:  # never let the update check break the tool
            _background["info"] = UpdateInfo(error=str(exc))

    thread = threading.Thread(target=worker, name="secure-repo-update-check", daemon=True)
    _background["thread"] = thread
    thread.start()


def background_result(timeout: float = 0.0) -> Optional[UpdateInfo]:
    thread = _background.get("thread")
    if thread is None:
        return None
    thread.join(timeout)  # type: ignore[attr-defined]
    return _background.get("info")  # type: ignore[return-value]


def pop_post_update_notice() -> Optional[Dict]:
    """Return (once) the information about an update installed in a previous session."""
    state = load_state()
    notice = state.pop("just_updated", None)
    if notice is not None:
        save_state(state)
    return notice


# ---------------------------------------------------------------------- installation
def _pip(args: List[str], log: Callable[[str], None]) -> subprocess.CompletedProcess:
    command = [sys.executable, "-m", "pip"] + args + ["--disable-pip-version-check"]
    log("$ python -m pip " + " ".join(args))
    return subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace",
                          stdin=subprocess.DEVNULL, timeout=900)


def _record_success(state: Dict, result: UpdateResult, info: UpdateInfo) -> None:
    state["just_updated"] = {"from": result.from_version, "to": result.to_version, "changes": info.changes[:15],
                             "date": time.strftime("%Y-%m-%d %H:%M")}
    state.pop("last_check", None)
    save_state(state)


def apply_update(info: Optional[UpdateInfo] = None, log: Callable[[str], None] = lambda _m: None,
                 project_dir: str = PROJECT_DIR) -> UpdateResult:
    install = detect_install(project_dir)
    info = info or check(force=True, project_dir=project_dir)
    result = UpdateResult(ok=False, message="", to_version=info.latest_version or "")
    lines: List[str] = []

    def note(message: str) -> None:
        lines.append(message)
        log(message)

    if info.error:
        result.message = f"Cannot check for updates: {info.error}"
        return result
    if not info.available:
        result.ok, result.message = True, f"Secure Repo {info.current_version} is already up to date."
        return result
    state = load_state()
    if install.mode == "git":
        root, branch = install.root, install.branch
        dirty = _git(root, "status", "--porcelain", "--untracked-files=no").strip()
        if dirty:
            files = ", ".join(line[3:] for line in dirty.splitlines()[:8])
            result.message = (f"Local changes in the Secure Repo folder prevent a safe update ({files}). "
                              f"Commit or stash them (git stash) and try again.")
            return result
        old = gitops.head_commit(root)
        note(f"Fetching {branch} from {install.remote or 'origin'}")
        _git(root, "fetch", "--quiet", "--no-tags", "origin", branch, timeout=120)
        try:
            _git(root, "merge", "--ff-only", "--quiet", "FETCH_HEAD", timeout=120)
        except gitops.GitError as exc:
            result.message = (f"The update cannot be applied as a fast-forward ({exc}). Your clone has its own "
                              f"commits; update it manually with git.")
            return result
        new = gitops.head_commit(root)
        note(f"Updated {old[:7]} -> {new[:7]}")
        changed = _git(root, "diff", "--name-only", old, new).splitlines()
        if any(name in ("pyproject.toml", "requirements.lock") for name in changed):
            note("Dependencies changed - refreshing them")
            requirements = os.path.join(root, "requirements.lock")
            completed = _pip(["install", "--quiet", "--require-hashes", "-r", requirements], note)
            if completed.returncode != 0:
                note(completed.stderr.strip()[-600:])
                result.message = ("Code updated, but refreshing dependencies failed. Run: "
                                  f"python -m pip install --require-hashes -r \"{requirements}\"")
                result.restart_required = True
                result.log = lines
                return result
        result.ok, result.restart_required = True, True
        with open(os.path.join(root, "secure_repo", "__init__.py"), encoding="utf-8") as handle:
            result.to_version = version_from_source(handle.read()) or info.latest_version
        result.message = (f"Secure Repo updated to {result.to_version} ({len(changed)} file(s) changed). "
                          f"Restart it to use the new version.")
        _record_success(state, result, info)
        result.log = lines
        return result

    # pip mode: install the exact upstream commit over HTTPS
    sha = info.latest_commit
    archive = f"https://github.com/{UPSTREAM}/archive/{sha}.zip"
    note(f"Installing {UPSTREAM}@{sha[:7]}")
    completed = _pip(["install", "--quiet", "--upgrade", archive], note)
    if completed.returncode != 0:
        output = (completed.stderr or completed.stdout).strip()
        if os.name == "nt" and ("WinError 32" in output or "WinError 5" in output):
            _schedule_deferred(archive, sha, info)
            result.deferred, result.ok, result.restart_required = True, True, True
            result.message = ("Windows locks the running Secure Repo executable. The update will be installed "
                              "automatically as soon as you close Secure Repo.")
            result.log = lines
            return result
        note(output[-800:])
        result.message = "pip could not install the update (see the log above)."
        result.log = lines
        return result
    state["installed_commit"] = sha
    result.ok, result.restart_required = True, True
    result.message = f"Secure Repo updated to {result.to_version or sha[:7]}. Restart it to use the new version."
    _record_success(state, result, info)
    result.log = lines
    return result


_DEFERRED_SCRIPT = r'''
import ctypes, json, subprocess, sys, time
pid, state_path, archive, sha, to_version = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
kernel32 = ctypes.windll.kernel32
handle = kernel32.OpenProcess(0x00100000, False, pid)  # SYNCHRONIZE
if handle:
    kernel32.WaitForSingleObject(handle, 600000)
    kernel32.CloseHandle(handle)
time.sleep(1)
done = subprocess.run([sys.executable, "-m", "pip", "install", "--quiet", "--upgrade", archive], capture_output=True, text=True)
try:
    with open(state_path, encoding="utf-8") as fh:
        state = json.load(fh)
except Exception:
    state = {}
if done.returncode == 0:
    state["installed_commit"] = sha
    state["just_updated"] = {"from": state.get("pending_from", ""), "to": to_version, "changes": state.get("pending_changes", []), "date": time.strftime("%Y-%m-%d %H:%M")}
    state.pop("last_check", None)
else:
    state["update_error"] = (done.stderr or done.stdout)[-1000:]
with open(state_path, "w", encoding="utf-8") as fh:
    json.dump(state, fh, indent=2)
'''


def _schedule_deferred(archive: str, sha: str, info: UpdateInfo) -> None:
    """Windows: finish the pip upgrade in a detached helper once this process exits."""
    state = load_state()
    state["pending_from"], state["pending_changes"] = __version__, info.changes[:15]
    save_state(state)
    script = os.path.join(data_dir(), "finish_update.py")
    with open(script, "w", encoding="utf-8") as handle:
        handle.write(_DEFERRED_SCRIPT)
    flags = 0x00000008 | 0x00000200  # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
    subprocess.Popen([sys.executable, script, str(os.getpid()), _state_path(), archive, sha, info.latest_version or sha[:7]],
                     creationflags=flags, close_fds=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL)
