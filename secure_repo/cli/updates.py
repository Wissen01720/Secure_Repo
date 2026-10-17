"""CLI presentation of update notices and the in-place installer."""

from __future__ import annotations


from rich import box
from rich.console import Group
from rich.markup import escape
from rich.panel import Panel
from rich.prompt import Confirm
from rich.text import Text

from secure_repo.cli.theme import CYAN, DIM, MAGENTA, NEON, VIOLET, console, say
from secure_repo.core import updater


def render_available(info: updater.UpdateInfo) -> None:
    """Big, hard-to-miss panel announcing that a new version can be installed."""
    head = Text()
    head.append("  NEW VERSION AVAILABLE  ", style=f"bold black on {NEON}")
    head.append(f"   {info.current_version}", style="bold white")
    head.append("  →  ", style=DIM)
    head.append(info.latest_version or info.latest_commit[:7], style=f"bold {NEON}")
    if info.commits_behind:
        head.append(f"   ({info.commits_behind} new change{'s' if info.commits_behind != 1 else ''})", style=CYAN)
    parts = [head, Text("")]
    if info.changes:
        parts.append(Text("WHAT'S NEW", style=f"bold {MAGENTA}"))
        for change in info.changes[:10]:
            sha, _, subject = change.partition(" ")
            parts.append(Text.assemble(("  ▸ ", NEON), (sha + " ", "grey50"), (subject, "white")))
        if len(info.changes) > 10:
            parts.append(Text(f"  ... and {len(info.changes) - 10} more", style=DIM))
        parts.append(Text(""))
    elif info.notes:
        parts.append(Text("WHAT'S NEW", style=f"bold {MAGENTA}"))
        for line in info.notes.splitlines()[1:12]:
            if line.strip():
                parts.append(Text("  " + line.strip(), style="white"))
        parts.append(Text(""))
    how = Text()
    how.append("Install it now without re-cloning: ", style=DIM)
    how.append("[U] in the main console", style=f"bold {NEON}")
    how.append("  or  ", style=DIM)
    how.append("secure-repo update", style=f"bold {CYAN}")
    parts.append(how)
    console.print(Panel(Group(*parts), title=Text(" ⟦ UPDATE ⟧ ", style=f"bold {NEON}"), border_style=NEON,
                        box=box.DOUBLE, padding=(1, 2)))


def render_post_update(notice: dict) -> None:
    body = Text()
    body.append("  UPDATE INSTALLED  ", style=f"bold black on {VIOLET}")
    body.append(f"   now running Secure Repo {notice.get('to') or ''}", style="bold white")
    if notice.get("from"):
        body.append(f"  (was {notice['from']})", style=DIM)
    changes = notice.get("changes") or []
    if changes:
        body.append("\n\nIncluded changes:\n", style=f"bold {MAGENTA}")
        for change in changes[:10]:
            body.append(f"  ▸ {change}\n", style="white")
    console.print(Panel(body, border_style=VIOLET, box=box.ROUNDED, padding=(1, 2)))


def render_compact(info: updater.UpdateInfo | None) -> None:
    if info and info.available:
        say(Text.assemble((info.summary, f"bold {NEON}"), (" - run ", DIM), ("secure-repo update", f"bold {CYAN}"),
                          (" to install it.", DIM)), "warn")


def install(info: updater.UpdateInfo | None = None, assume_yes: bool = False) -> updater.UpdateResult | None:
    """Interactive installation. Returns the result (None if the user declined or nothing to install)."""
    with console.status(Text(" Checking the upstream repository...", style=DIM), spinner="dots12", spinner_style=NEON):
        info = info if (info and info.available) else updater.check(force=True)
    if info.error:
        say(f"Update check failed: {escape(info.error)}", "error")
        return None
    if not info.available:
        say(info.summary, "ok")
        return None
    render_available(info)
    mode = updater.detect_install()
    how = ("git fast-forward in " + (mode.root or "")) if mode.mode == "git" else (
        f"pip install of {updater.UPSTREAM}@{info.latest_commit[:7]} from GitHub")
    console.print(Text(f"  Method: {how}", style=DIM))
    if not assume_yes and not Confirm.ask(Text.assemble(("[?] ", f"bold {VIOLET}"), ("Install the update now?", "bold white")),
                                          console=console, default=True):
        say("Update postponed. You can install it later from the main console or with 'secure-repo update'.", "info")
        return None
    with console.status(Text(" Installing update...", style=DIM), spinner="dots12", spinner_style=NEON):
        result = updater.apply_update(info, log=lambda message: console.print(Text(f"  {message}", style="grey50")))
    say(result.message, "ok" if result.ok else "error")
    if result.ok and result.restart_required and not result.deferred:
        console.print(Panel(Text.assemble(("Restart Secure Repo to use the new version: ", "white"),
                                          ("close this session and run it again", f"bold {NEON}")),
                            border_style=NEON, box=box.ROUNDED))
    return result


def cmd_update(args) -> int:
    if args.check:
        with console.status(Text(" Checking for updates...", style=DIM), spinner="dots12", spinner_style=NEON):
            info = updater.check(force=True)
        if info.error:
            say(f"Update check failed: {escape(info.error)}", "error")
            return 1
        if info.available:
            render_available(info)
            return 10  # distinct exit code: an update is available (useful in scripts)
        say(info.summary, "ok")
        return 0
    result = install(assume_yes=args.yes)
    if result is None:
        return 0
    return 0 if result.ok else 1
