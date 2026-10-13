"""Interactive terminal menus."""

from __future__ import annotations

import os
import platform
import subprocess
import sys
import webbrowser
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from rich import box
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text

from secure_repo.cli import views
from secure_repo.cli.banner import section
from secure_repo.cli.dashboard import LiveDashboard
from secure_repo.cli.theme import CYAN, DIM, MAGENTA, NEON, VIOLET, console, say
from secure_repo.core import compliance, gitops, updater
from secure_repo.core.events import EventBus
from secure_repo.core.models import SEVERITIES, SUPPRESSED_STATUSES
from secure_repo.core.rules import RULES
from secure_repo.core.scanner import Scanner, ScanOptions
from secure_repo.core.workspace import Target, discover_branches


@dataclass
class SessionState:
    options: ScanOptions = field(default_factory=ScanOptions)
    animate: bool = True
    plain: bool = False
    assume_yes: bool = False
    authorized: Set[str] = field(default_factory=set)
    # Access tokens per host for private repositories: memory only, never written anywhere.
    credentials: Dict[str, gitops.GitCredentials] = field(default_factory=dict, repr=False)


def ask(prompt: str, **kwargs) -> str:
    return Prompt.ask(Text.assemble(("[?] ", f"bold {VIOLET}"), (prompt, "bold white")), console=console, **kwargs)


def confirm(prompt: str, default: bool = False) -> bool:
    return Confirm.ask(Text.assemble(("[?] ", f"bold {VIOLET}"), (prompt, "bold white")), console=console,
                       default=default)


# ---------------------------------------------------------------------- helpers
def open_path(path: str) -> None:
    try:
        if path.lower().endswith(".html"):
            webbrowser.open(Path(path).resolve().as_uri())
        elif platform.system() == "Windows":
            os.startfile(path)  # type: ignore[attr-defined]  # noqa: S606  # nosec - opens a local report folder
        elif platform.system() == "Darwin":
            subprocess.run(["open", path], check=False)
        else:
            subprocess.run(["xdg-open", path], check=False)
        say(f"Opened {path}", "ok")
    except OSError as exc:
        say(f"Could not open {path}: {exc}", "error")


def confirm_authorization(target: Target, state: SessionState) -> bool:
    key = f"{target.kind}:{target.location}"
    if state.assume_yes or key in state.authorized:
        return True
    panel = Text()
    panel.append("RULES OF ENGAGEMENT\n\n", style=f"bold {MAGENTA}")
    panel.append("Only audit repositories you own or have explicit, written permission to assess.\n", style="white")
    panel.append("Secure Repo is read-only: it never executes target code, never exploits findings and redacts "
                 "secrets in every report.\nUnauthorized access to systems or data may be illegal in your "
                 "jurisdiction.", style=DIM)
    console.print(Panel(panel, border_style=MAGENTA, box=box.DOUBLE, padding=(1, 2)))
    if not console.is_terminal:
        say("Authorization cannot be confirmed in non-interactive mode. Re-run with --yes to confirm.", "error")
        return False
    if confirm(f"I confirm I am authorized to audit {target.location}", default=False):
        state.authorized.add(key)
        return True
    say("Authorization not confirmed - operation cancelled.", "warn")
    return False


def _interactive() -> bool:
    return console.is_terminal and sys.stdin is not None and sys.stdin.isatty()


def request_credentials(target: Target, state: SessionState, error: gitops.GitAuthError) -> bool:
    """Ask for an access token after the remote rejected the request. Returns True when one was entered."""
    host = gitops.host_of(target.location)
    if not gitops.is_https(target.location):
        say("This is an SSH URL: load an SSH key with access to the repository (ssh-add) or use the https:// URL "
            "with an access token.", "info")
        return False
    if not _interactive():
        say("Non-interactive mode: export the token in SECURE_REPO_GIT_TOKEN (or GH_TOKEN / GITLAB_TOKEN) or pass "
            "--token-env VARIABLE_NAME.", "info")
        return False
    body = Text()
    body.append("PRIVATE REPOSITORY - ACCESS TOKEN REQUIRED\n\n", style=f"bold {MAGENTA}")
    body.append(gitops.auth_help(target.location, error.sso) + "\n\n", style="white")
    body.append(f"The token is kept in memory for this session only, sent to Git as an authorization header "
                f"scoped to {host}, and never written to disk, logs or reports.", style=DIM)
    console.print(Panel(body, border_style=MAGENTA, box=box.ROUNDED, padding=(1, 2)))
    token = Prompt.ask(Text.assemble(("[?] ", f"bold {VIOLET}"), ("Access token (input hidden, Enter to cancel)",
                                                                   "bold white")),
                       console=console, password=True, default="", show_default=False).strip()
    if not token:
        say("No token entered - operation cancelled.", "warn")
        return False
    username = ask(f"Username (Enter = '{gitops.default_username(target.location)}', the default for "
                   f"{gitops.provider_of(target.location)})", default="", show_default=False).strip()
    credentials = gitops.GitCredentials(token, username)
    target.credentials = credentials
    state.credentials[host] = credentials
    return True


def discover_with_auth(target: Target, state: SessionState) -> List[gitops.Branch]:
    """Discover branches; for private remotes ask for an access token and retry (3 attempts)."""
    if target.kind == "remote" and not target.credentials:
        target.credentials = state.credentials.get(gitops.host_of(target.location))
    attempts = 0
    while True:
        try:
            with console.status(Text(" Enumerating branches (git ls-remote / for-each-ref)...", style=DIM),
                                spinner="dots12", spinner_style=NEON):
                return discover_branches(target, interactive=False)
        except gitops.GitAuthError as exc:
            if target.credentials:
                state.credentials.pop(gitops.host_of(target.location), None)
                target.credentials = None
                say("The access token was rejected (wrong token, missing scope or SSO not authorized).", "warn")
            attempts += 1
            if attempts > 3 or not request_credentials(target, state, exc):
                raise


def choose_branch(target: Target, state: SessionState) -> Tuple[bool, Optional[str]]:
    """Return (ok, branch). branch None means working tree / default branch."""
    section("BRANCH RECON", CYAN)
    try:
        branches = discover_with_auth(target, state)
    except gitops.GitAuthError as exc:
        say(f"Access denied: {exc}", "error")
        return False, None
    except gitops.GitError as exc:
        say(f"Branch discovery failed: {exc}", "error")
        return False, None
    if not branches:
        if target.kind == "local":
            say("Not a Git repository (or git is unavailable) - the folder will be scanned as-is.", "warn")
            return True, None
        say("The remote repository has no branches.", "error")
        return False, None

    table = Table(box=box.SIMPLE_HEAVY, header_style=f"bold {CYAN}")
    table.add_column("#", justify="right", style=f"bold {NEON}")
    table.add_column("Branch", style="bold white")
    table.add_column("Type", style=DIM)
    table.add_column("Commit", style="grey62")
    table.add_column("Last commit", style=DIM)
    table.add_column("", style=MAGENTA)
    default_index = 1
    for index, branch in enumerate(branches, 1):
        marker = "◀ current (working tree)" if branch.current else ("◀ default" if branch.default else "")
        if branch.current or branch.default:
            default_index = index
        table.add_row(str(index), branch.name, "remote" if branch.remote else "local", branch.commit, branch.date or "-",
                      marker)
    console.print(table)
    say(f"{len(branches)} branch(es) discovered.", "ok")
    while True:
        answer = ask("Select a branch to audit (number or name)", default=str(default_index)).strip()
        chosen = None
        if answer.isdigit() and 1 <= int(answer) <= len(branches):
            chosen = branches[int(answer) - 1]
        else:
            chosen = next((b for b in branches if b.name == answer), None)
        if chosen:
            say(f"Branch locked: {chosen.name}", "ok")
            if target.kind == "local" and chosen.current:
                return True, None
            return True, chosen.name
        say("Invalid selection, try again.", "warn")


def run_scan(target: Target, state: SessionState) -> Tuple[Optional[Dict], Optional[str]]:
    bus = EventBus()
    scanner = Scanner(state.options, bus)
    label = target.location
    dashboard = LiveDashboard(label, target.branch or "working tree / default", plain=state.plain)
    bus.subscribe(dashboard.handle)
    section("ENGAGEMENT STARTED", MAGENTA)
    try:
        with dashboard:
            report, report_dir = scanner.run(target, interactive=False)
    except KeyboardInterrupt:
        scanner.cancelled = True
        say("Operation aborted by user. Temporary files were cleaned up.", "warn")
        return None, None
    except gitops.GitAuthError as exc:
        say(f"Access denied: {exc}", "error")
        return None, None
    except gitops.GitError as exc:
        say(f"Git error: {exc}", "error")
        return None, None
    except FileNotFoundError as exc:
        say(str(exc), "error")
        return None, None
    except Exception as exc:  # pragma: no cover - surfaced to the user
        say(f"Scan failed: {exc}", "error")
        return None, None
    views.render_summary(report, report_dir)
    return report, report_dir


# ---------------------------------------------------------------------- post scan
def browse_findings(report: Dict) -> None:
    findings = report["findings"]
    if not findings:
        say("There are no findings to browse.", "ok")
        return
    while True:
        counts = report["summary"]["by_severity"]
        options = " ".join(f"{s}({counts[s]})" for s in SEVERITIES if counts[s])
        answer = ask(f"Filter by severity [all {options}], 'suppressed', or a finding ID (e.g. SR-0001), 'q' to go back",
                     default="all").strip()
        if answer.lower() in ("q", "quit", "back", "0"):
            return
        upper = answer.upper()
        match = next((f for f in findings if f["id"] == upper), None)
        if match:
            views.render_finding_detail(report, match)
            continue
        active = [f for f in findings if f.get("status") not in SUPPRESSED_STATUSES]
        if answer.lower() in SEVERITIES:
            subset = [f for f in active if f["severity"] == answer.lower()]
        elif answer.lower() == "all":
            subset = active
        elif answer.lower() == "suppressed":
            subset = [f for f in findings if f.get("status") in SUPPRESSED_STATUSES]
        else:
            subset = [f for f in findings if answer.lower() in (f["title"] + f["file"] + f["rule_id"]).lower()]
        views.render_findings_table(subset, limit=60, title=f"FINDINGS · {answer}")
        say("Type a finding ID to read why it is insecure and how to fix it.", "info")


def post_scan_menu(report: Dict, report_dir: Optional[str], state: SessionState) -> None:
    if not console.is_terminal:
        return
    while True:
        section("POST-SCAN ACTIONS", VIOLET)
        items = [
            ("1", "Browse findings & explanations"),
            ("2", "Triage findings - mark false positives / accepted risk (the engine learns)"),
            ("3", "Repository structure (boxes + tree)"),
            ("4", "Full library inventory + virtual lockfile"),
            ("5", "Compliance details" + ("" if report["compliance"].get("enabled") else " (audit was disabled)")),
            ("6", "Analysis quality (engines, noise discarded, suppressed findings)"),
            ("7", "Open interactive HTML report in the browser"),
            ("8", "Open the report folder"),
            ("9", "Explore these results in the GUI"),
            ("0", "Back to main menu"),
        ]
        _print_menu(items)
        choice = ask("Select an action", choices=[i[0] for i in items], default="0", show_choices=False)
        if choice == "1":
            browse_findings(report)
        elif choice == "2":
            from secure_repo.cli.learning import interactive_triage

            interactive_triage(report, report_dir)
        elif choice == "3":
            views.render_structure_boxes(report["structure"], max_boxes=24)
            views.render_structure_tree(report["structure"])
        elif choice == "4":
            views.render_dependencies(report)
            views.render_lockfile(report)
        elif choice == "5":
            if report["compliance"].get("enabled"):
                views.render_compliance(report, detailed=True)
            else:
                say("Enable the compliance audit in Settings (or use --compliance) and scan again.", "warn")
        elif choice == "6":
            views.render_quality(report, detailed=True)
        elif choice == "7" and report_dir:
            open_path(os.path.join(report_dir, "report.html"))
        elif choice == "8" and report_dir:
            open_path(report_dir)
        elif choice == "9":
            from secure_repo.gui.server import serve

            serve(state.options, open_browser=True, preload_report=report, preload_dir=report_dir)
        elif choice == "0":
            return


# ---------------------------------------------------------------------- settings
def settings_menu(state: SessionState) -> None:
    opts = state.options
    while True:
        section("SCAN SETTINGS", CYAN)
        frameworks = ", ".join(compliance.resolve_frameworks(opts.frameworks)) if opts.compliance else "-"
        items = [
            ("1", f"Compliance audit ............ {'ON' if opts.compliance else 'OFF'}  [{frameworks}]"),
            ("2", f"Online vulnerability intel .. {'OFF (offline mode)' if opts.offline else 'ON (OSV.dev + deps.dev)'}"),
            ("3", f"Include test files .......... {'YES' if opts.include_tests else 'NO'}"),
            ("4", f"Max file size ............... {opts.max_file_size // 1024} KB"),
            ("5", f"Output folder ............... {os.path.abspath(opts.output_dir)}"),
            ("6", f"Exclude patterns ............ {', '.join(opts.exclude) or '-'}"),
            ("7", f"Auditor name (audit trail) .. {opts.auditor or '-'}"),
            ("8", f"Animations .................. {'ON' if state.animate else 'OFF'}"),
            ("9", f"Minimum confidence .......... {opts.min_confidence.upper()}"),
            ("10", f"Learning from triage ........ {'ON' if opts.learning else 'OFF'}"),
            ("11", f"Analysis engine ............. {'LAYERED (masking + AST + data flow)' if opts.semantic else 'PATTERNS (legacy)'}"),
            ("12", f"Virtual lockfile resolution . {'ON' if opts.resolve_versions else 'OFF'}"),
            ("13", f"Repo config authority ....... {'TRUST ALWAYS' if opts.trust_repo_config else ('NEVER' if opts.trust_repo_config is False else 'AUTO (only local working tree)')}"),
            ("0", "Back"),
        ]
        _print_menu(items)
        choice = ask("Change setting", choices=[i[0] for i in items], default="0", show_choices=False)
        if choice == "1":
            opts.compliance = confirm("Enable the compliance audit?", default=not opts.compliance)
            if opts.compliance:
                choose_frameworks(state)
        elif choice == "2":
            opts.offline = not opts.offline
        elif choice == "3":
            opts.include_tests = not opts.include_tests
        elif choice == "4":
            value = ask("Max file size in KB", default=str(opts.max_file_size // 1024))
            if value.isdigit() and int(value) > 0:
                opts.max_file_size = int(value) * 1024
        elif choice == "5":
            opts.output_dir = ask("Output folder", default=opts.output_dir)
        elif choice == "6":
            raw = ask("Glob patterns to exclude (comma separated, empty to clear)", default=",".join(opts.exclude))
            opts.exclude = [p.strip() for p in raw.split(",") if p.strip()]
        elif choice == "7":
            opts.auditor = ask("Auditor name / organisation", default=opts.auditor or "")
        elif choice == "8":
            state.animate = not state.animate
        elif choice == "9":
            opts.min_confidence = ask("Minimum confidence", choices=["low", "medium", "high"], default=opts.min_confidence)
        elif choice == "10":
            opts.learning = not opts.learning
        elif choice == "11":
            opts.semantic = not opts.semantic
        elif choice == "12":
            opts.resolve_versions = not opts.resolve_versions
        elif choice == "13":
            opts.trust_repo_config = {None: True, True: False, False: None}[opts.trust_repo_config]
        elif choice == "0":
            return


def choose_frameworks(state: SessionState) -> None:
    frameworks = compliance.list_frameworks()
    table = Table(box=box.SIMPLE, header_style=f"bold {VIOLET}")
    table.add_column("#", style=f"bold {NEON}", justify="right")
    table.add_column("Framework", style="bold white")
    table.add_column("Version", style=DIM)
    table.add_column("Controls", justify="right")
    table.add_column("Scope", style=DIM, overflow="fold")
    for index, fw in enumerate(frameworks, 1):
        table.add_row(str(index), fw["name"], fw["version"], str(fw["controls"]), fw["description"])
    console.print(table)
    raw = ask("Frameworks to evaluate (numbers separated by commas, or 'all')", default="all").strip().lower()
    if raw == "all":
        state.options.frameworks = ["all"]
        return
    picked: List[str] = []
    for part in raw.split(","):
        part = part.strip()
        if part.isdigit() and 1 <= int(part) <= len(frameworks):
            picked.append(frameworks[int(part) - 1]["id"])
    state.options.frameworks = picked or ["all"]
    say("Compliance frameworks: " + ", ".join(compliance.resolve_frameworks(state.options.frameworks)), "ok")


# ---------------------------------------------------------------------- main menu
def _print_menu(items: List[Tuple[str, str]], highlight: Optional[str] = None) -> None:
    for key, label in items:
        line = Text("  ")
        if key == highlight:
            line.append(f"[{key}]", style=f"bold black on {NEON}")
            line.append(f"  {label}", style=f"bold {NEON}")
        else:
            line.append(f"[{key}]", style=f"bold {NEON}" if key != "0" else "bold #ff2e63")
            line.append(f"  {label}", style="white")
        console.print(line)
    console.print()


def help_panel() -> None:
    guide = Text()
    guide.append("QUICK FIELD GUIDE\n\n", style=f"bold {NEON}")
    rows = [
        ("secure-repo", "interactive menu (this screen)"),
        ("secure-repo scan", "audit the repository in the current directory"),
        ("secure-repo scan <git-url>", "list remote branches, pick one, clone & audit"),
        ("secure-repo scan <path> -b dev", "audit branch 'dev' of a local repository"),
        ("secure-repo scan . --compliance", "include the compliance audit (all frameworks)"),
        ("secure-repo scan . --compliance pci-dss,gdpr", "only selected frameworks"),
        ("secure-repo scan . --offline", "no network lookups (static analysis only)"),
        ("secure-repo scan . --fail-on high", "exit code 3 when high+ findings exist (CI)"),
        ("secure-repo branches <git-url|path>", "only list branches"),
        ("secure-repo gui", "launch the graphical interface in your browser"),
        ("secure-repo rules --search sql", "list detection rules"),
        ("secure-repo frameworks", "list compliance frameworks"),
        ("secure-repo scan <url> --ask-token", "private repo: prompt for an access token (hidden)"),
        ("secure-repo scan <url> --token-env VAR", "private repo in CI: token read from an env variable"),
        ("secure-repo update", "install the latest version without re-cloning"),
        ("secure-repo update --check", "only check whether a new version exists"),
    ]
    for command, description in rows:
        guide.append(f"  $ {command:<46}", style=f"bold {CYAN}")
        guide.append(f"{description}\n", style=DIM)
    guide.append("\nReports go to the Secure Repo data folder (reports/<repo>_<branch>_<timestamp>/), outside the audited repo.",
                 style=MAGENTA)
    console.print(Panel(guide, border_style=CYAN, box=box.ROUNDED, padding=(1, 2)))


def main_menu(state: SessionState) -> int:
    cwd = os.getcwd()
    repo_root = gitops.find_repo_root(cwd)
    current = gitops.current_branch(repo_root) if repo_root else None
    while True:
        section("MAIN CONSOLE", NEON)
        items: List[Tuple[str, str]] = []
        if repo_root:
            items.append(("1", f"Audit THIS repository  →  {repo_root}  @ {current or 'detached'}"))
        else:
            items.append(("1", "Audit the current folder (not a Git repository)"))
        items += [
            ("2", "Audit a REMOTE repository by Git URL (https / ssh)"),
            ("3", "Audit a LOCAL repository or folder by path"),
            ("4", "Launch the GRAPHICAL interface (GUI)"),
            ("5", f"Settings  [compliance: {'ON' if state.options.compliance else 'OFF'} · "
                  f"intel: {'OFF' if state.options.offline else 'ON'} · output: {state.options.output_dir}]"),
            ("6", f"List detection rules ({len(RULES)})"),
            ("7", "Usage guide"),
        ]
        update_info = updater.background_result(timeout=0)
        if update_info is not None and update_info.available:
            items.append(("U", f"INSTALL UPDATE  {update_info.current_version} → "
                               f"{update_info.latest_version or update_info.latest_commit[:7]}  "
                               f"({update_info.commits_behind or 'new'} change(s)) - no re-cloning needed"))
        else:
            items.append(("U", "Check for updates of Secure Repo"))
        items.append(("0", "Exit"))
        _print_menu(items, highlight="U" if update_info is not None and update_info.available else None)
        try:
            choice = ask("root@secure-repo:~#", choices=[i[0] for i in items] + ["u"], default="1",
                         show_choices=False).strip().upper()
        except (KeyboardInterrupt, EOFError):
            console.print()
            return 0
        try:
            if choice in ("1", "2", "3"):
                if choice == "1":
                    target = Target.parse(repo_root or cwd)
                elif choice == "2":
                    url = ask("Git URL (e.g. https://github.com/owner/repo.git)").strip()
                    if not gitops.is_git_url(url):
                        say("That does not look like a supported Git URL.", "error")
                        continue
                    target = Target.parse(url)
                else:
                    path = ask("Path to the repository or folder", default=cwd).strip().strip('"')
                    target = Target.parse(path)
                    if not os.path.isdir(target.location):
                        say(f"Directory not found: {target.location}", "error")
                        continue
                if not confirm_authorization(target, state):
                    continue
                ok, branch = choose_branch(target, state)
                if not ok:
                    continue
                target.branch = branch
                if not state.options.compliance and confirm("Run the optional compliance audit as well?", default=False):
                    state.options.compliance = True
                    choose_frameworks(state)
                report, report_dir = run_scan(target, state)
                if report:
                    post_scan_menu(report, report_dir, state)
            elif choice == "4":
                from secure_repo.gui.server import serve

                serve(state.options, open_browser=True)
            elif choice == "5":
                settings_menu(state)
            elif choice == "6":
                views.render_rules(RULES)
            elif choice == "7":
                help_panel()
            elif choice == "U":
                from secure_repo.cli import updates as update_views

                result = update_views.install(update_info if update_info and update_info.available else None)
                if result is not None and result.ok and result.restart_required:
                    say("Closing Secure Repo so the new version is loaded on the next start.", "ok")
                    return 0
            elif choice == "0":
                say("Session closed. Stay safe.", "ok")
                return 0
        except KeyboardInterrupt:
            console.print()
            say("Interrupted - back to the main console.", "warn")
