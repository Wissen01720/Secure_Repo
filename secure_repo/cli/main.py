"""Entry point: ``secure-repo`` / ``python -m secure_repo``."""

from __future__ import annotations

import argparse
import os
import platform
import sys
from typing import List, Optional

from rich import box
from rich.table import Table
from rich.text import Text

from secure_repo import __author__, __version__
from secure_repo.cli import views
from secure_repo.cli.banner import boot_sequence, section, show_banner
from secure_repo.cli import updates as update_views
from secure_repo.cli.menu import (SessionState, choose_branch, confirm_authorization, discover_with_auth, main_menu,
                                  open_path, post_scan_menu, run_scan)
from secure_repo.cli.theme import CYAN, DIM, NEON, VIOLET, console, say
from secure_repo.core import compliance, gitops, triage, updater
from secure_repo.core.models import SEVERITIES, SEVERITY_RANK, SUPPRESSED_STATUSES
from secure_repo.core.rules import RULES
from secure_repo.core.scanner import ScanOptions
from secure_repo.core.workspace import Target

EPILOG = """examples:
  secure-repo                                   interactive menu
  secure-repo scan                              audit the repository in the current directory
  secure-repo scan https://github.com/o/r.git   pick a remote branch, clone (depth 1) and audit it
  secure-repo scan ../project -b develop        audit branch 'develop' without touching your working tree
  secure-repo scan . --compliance pci-dss,gdpr  add the compliance audit for selected frameworks
  secure-repo scan . --offline --fail-on high   CI mode: no network, exit code 3 on high+ findings
  secure-repo scan . --min-confidence medium   hide low-confidence findings (kept in the audit trail)
  secure-repo branches https://github.com/o/r   list remote branches
  secure-repo gui                               open the graphical interface in your browser
  secure-repo triage stats                      precision of every rule according to your triage decisions
  secure-repo benchmark                         measure precision/recall of the engines on the labeled corpus
  secure-repo init-config                       create a .securerepo.toml to tune the analysis for a project

Only audit repositories you own or are explicitly authorized to assess."""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secure-repo", formatter_class=argparse.RawDescriptionHelpFormatter, epilog=EPILOG,
        description="Secure Repo - repository security auditor (static analysis, secrets, libraries, "
                    "supply chain and optional compliance audit).")
    parser.add_argument("--version", action="version", version=f"Secure Repo {__version__} by {__author__}")
    parser.add_argument("--no-anim", dest="root_no_anim", action="store_true", help="disable terminal animations")
    parser.add_argument("--no-update-check", action="store_true",
                        help="do not check for new versions of Secure Repo (also: SECURE_REPO_NO_UPDATE_CHECK=1)")
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    scan = sub.add_parser("scan", help="audit a repository (local path, current directory or Git URL)",
                          formatter_class=argparse.RawDescriptionHelpFormatter, epilog=EPILOG)
    scan.add_argument("target", nargs="?", default=".", help="path or Git URL (default: current directory)")
    scan.add_argument("-b", "--branch", help="branch to audit (skips the interactive branch picker)")
    scan.add_argument("--compliance", nargs="?", const="all", default=None, metavar="FRAMEWORKS",
                      help="enable the compliance audit: 'all' or comma list "
                           f"({', '.join(compliance.FRAMEWORKS)})")
    scan.add_argument("--offline", action="store_true", help="disable OSV.dev / deps.dev lookups")
    scan.add_argument("--no-enrich", action="store_true", help="skip license/latest-version lookups (deps.dev)")
    scan.add_argument("-o", "--output", default=None, metavar="DIR",
                      help="reports folder (default: the Secure Repo data folder, outside the audited repo)")
    scan.add_argument("-y", "--yes", action="store_true", help="confirm you are authorized to audit the target")
    scan.add_argument("--no-tests", action="store_true", help="skip files that look like tests/fixtures")
    scan.add_argument("-j", "--jobs", type=int, default=0, metavar="N",
                      help="worker processes for file analysis (default 0 = automatic; 1 = a single process)")
    scan.add_argument("--max-file-size", type=int, default=2048, metavar="KB", help="skip larger files (default 2048)")
    scan.add_argument("--exclude", action="append", default=[], metavar="GLOB", help="exclude paths (repeatable)")
    scan.add_argument("--auditor", default="", help="auditor name recorded in the audit trail")
    scan.add_argument("--fail-on", choices=SEVERITIES, help="exit with code 3 if findings of this severity or worse exist")
    scan.add_argument("--plain", action="store_true", help="plain line output (no live dashboard)")
    scan.add_argument("--no-anim", action="store_true", help="disable animations")
    scan.add_argument("--no-menu", action="store_true", help="do not show the post-scan menu")
    scan.add_argument("--open", action="store_true", help="open the HTML report when finished")
    scan.add_argument("--token-env", metavar="VARIABLE",
                        help="read the access token for a private https repository from this environment variable "
                             "(never pass the token itself on the command line)")
    scan.add_argument("--ask-token", action="store_true",
                        help="prompt for the access token (hidden input) before contacting the repository")
    scan.add_argument("--min-confidence", choices=("low", "medium", "high"), default="low",
                      help="filter findings below this confidence (they stay in the report as 'filtered')")
    trust = scan.add_mutually_exclusive_group()
    trust.add_argument("--trust-repo-config", action="store_true",
                       help="apply the audited repository's own .securerepo.toml, shared triage and inline "
                            "suppressions even when it is a remote repository or another branch")
    trust.add_argument("--ignore-repo-config", action="store_true",
                       help="never apply the audited repository's own configuration, shared triage or inline "
                            "suppressions, not even for the local working tree")
    scan.add_argument("--no-learning", action="store_true",
                      help="ignore the triage knowledge base (decisions, learned patterns, rule statistics)")
    scan.add_argument("--no-resolve", action="store_true",
                      help="do not resolve versions of unpinned dependencies (virtual lockfile)")
    scan.add_argument("--private", action="append", default=[], metavar="GLOB",
                      help="package name pattern that must never be sent to any service, e.g. '@acme/*' (repeatable; "
                           "also [intel] private in .securerepo.toml)")
    scan.add_argument("--no-registry", action="store_true",
                      help="do not query package registries (deps.dev, Packagist, pub.dev); OSV.dev advisories still run")
    scan.add_argument("--check-confusion", action="store_true",
                      help="opt in: look the --private names up in the public registry to flag dependency confusion "
                           "(this sends those names)")
    scan.add_argument("--ca-bundle", default="", metavar="PATH",
                      help="CA certificate bundle for HTTPS lookups (also SECURE_REPO_CA_BUNDLE, REQUESTS_CA_BUNDLE, "
                           "SSL_CERT_FILE) - for networks that inspect TLS")
    scan.add_argument("--no-cache", action="store_true", help="do not keep registry/advisory lookups on disk for 24 hours")
    scan.add_argument("--max-registry", type=int, default=300, metavar="N",
                      help="direct dependencies resolved against package registries (default 300)")
    scan.add_argument("--max-graph", type=int, default=120, metavar="N",
                      help="direct dependencies whose transitive graph is expanded (default 120)")
    scan.add_argument("--max-enrich", type=int, default=250, metavar="N",
                      help="direct dependencies that get license / latest-version metadata (default 250)")
    scan.add_argument("--baseline", default="", metavar="REPORT_JSON",
                      help="an earlier report.json: --fail-on then counts only findings that are new")
    scan.add_argument("--since", default="", metavar="REF",
                      help="analyze only the files that changed relative to a Git reference (e.g. origin/main)")
    scan.add_argument("--engine", choices=("layered", "patterns"), default="layered",
                      help="'layered' (default): masking + syntax tree + data flow; 'patterns': legacy regex only")

    branches = sub.add_parser("branches", help="list the branches of a local repository or Git URL")
    branches.add_argument("target", nargs="?", default=".")
    branches.add_argument("--token-env", metavar="VARIABLE",
                        help="read the access token for a private https repository from this environment variable "
                             "(never pass the token itself on the command line)")
    branches.add_argument("--ask-token", action="store_true",
                        help="prompt for the access token (hidden input) before contacting the repository")

    gui = sub.add_parser("gui", help="launch the graphical interface (local web app)")
    gui.add_argument("--port", type=int, default=0, help="port (default: random free port)")
    gui.add_argument("--no-browser", action="store_true", help="do not open the browser automatically")
    gui.add_argument("-o", "--output", default=None, metavar="DIR", help="reports folder (default: Secure Repo data folder)")
    gui.add_argument("--offline", action="store_true", help="default the GUI to offline mode")

    rules = sub.add_parser("rules", help="list detection rules")
    rules.add_argument("--search", default="", help="filter by text (id, title, language, CWE)")

    sub.add_parser("frameworks", help="list compliance frameworks")

    update = sub.add_parser("update", help="check for and install a new version of Secure Repo (no re-cloning)")
    update.add_argument("--check", action="store_true", help="only check; exit code 10 when an update is available")
    update.add_argument("-y", "--yes", action="store_true", help="install without asking for confirmation")

    tri = sub.add_parser("triage", help="manage the triage knowledge base (false positives, learned patterns)")
    tri_sub = tri.add_subparsers(dest="triage_command", metavar="<action>")
    tri_list = tri_sub.add_parser("list", help="list recorded decisions and learned patterns")
    tri_list.add_argument("--status", choices=("confirmed", "accepted_risk", "false_positive"))
    tri_sub.add_parser("stats", help="per-rule precision computed from your decisions")
    tri_mark = tri_sub.add_parser("mark", help="triage findings of a report.json from the command line")
    tri_mark.add_argument("report", help="path to a report folder or its report.json")
    tri_mark.add_argument("ids", nargs="+", help="finding IDs, e.g. SR-0004 SR-0007")
    tri_mark.add_argument("--status", required=True, choices=("open", "confirmed", "accepted_risk", "false_positive"))
    tri_mark.add_argument("--reason", default="", help="justification (required for false positives)")
    tri_mark.add_argument("--scope", default="finding", choices=("finding", "project-pattern", "global-pattern"))
    tri_forget = tri_sub.add_parser("forget", help="delete a decision (fingerprint) or a learned pattern (id)")
    tri_forget.add_argument("identifier")
    tri_export = tri_sub.add_parser("export", help="export the knowledge base (or --to-repo to share with a team)")
    tri_export.add_argument("file", nargs="?", default="securerepo-knowledge.json")
    tri_export.add_argument("--to-repo", metavar="REPO_PATH",
                            help="write the decisions of that repository to <repo>/.securerepo/triage.json")
    tri_import = tri_sub.add_parser("import", help="import a knowledge base export")
    tri_import.add_argument("file")
    tri_cases = tri_sub.add_parser("export-cases", help="turn false positives into benchmark regression cases")
    tri_cases.add_argument("directory", nargs="?", default=None)
    tri_reset = tri_sub.add_parser("reset", help="erase every decision and learned pattern")
    tri_reset.add_argument("--yes", action="store_true")

    bench = sub.add_parser("benchmark", help="measure precision/recall of the detection engines")
    bench.add_argument("--cases", action="append", default=[], metavar="DIR", help="additional labeled case folders")
    bench.add_argument("--rule", default="", help="only show rules containing this text")
    bench.add_argument("--compare", action="store_true", help="also run the legacy pattern-only engine")
    bench.add_argument("--external", action="store_true",
                       help="audit real third-party repositories pinned to a commit and score the findings against "
                            "hand-labelled verdicts (needs git; --fetch downloads them)")
    bench.add_argument("--fetch", action="store_true", help="with --external: download the pinned repositories first")
    bench.add_argument("--dir", default=None, metavar="DIR", help="with --external: folder holding the repositories")
    bench.add_argument("--only", action="append", default=[], metavar="NAME", help="with --external: limit to a repository")
    bench.add_argument("--min-precision", type=float, default=0.0, metavar="P",
                       help="with --external: exit 1 if the precision of medium/high-confidence findings is below P (0-1)")
    bench.add_argument("--min-recall", type=float, default=0.0, metavar="R",
                       help="with --external: exit 1 if the recall of documented weaknesses is below R (0-1)")

    init = sub.add_parser("init-config", help="create a .securerepo.toml template in a repository")
    init.add_argument("path", nargs="?", default=".")
    return parser


def _boot(state: SessionState) -> None:
    git_ok = gitops.git_available()
    cwd = os.getcwd()
    root = gitops.find_repo_root(cwd) if git_ok else None
    checks = [
        ("ok", "Core engine", f"Secure Repo {__version__}"),
        ("ok", "Detection signatures", f"{len(RULES)} rules loaded"),
        ("ok", "Compliance frameworks", f"{len(compliance.FRAMEWORKS)} available (optional)"),
        ("ok" if git_ok else "fail", "Git engine", gitops.git_version() if git_ok else "NOT FOUND - install git"),
        ("warn" if state.options.offline else "ok", "Vulnerability intelligence",
         "offline mode" if state.options.offline else "OSV.dev + deps.dev (online)"),
        ("info", "Host platform", f"{platform.system()} {platform.release()} · Python {platform.python_version()}"),
        ("info", "Working directory", f"Git repo @ {gitops.current_branch(root) or 'detached'}" if root
         else "not a Git repository"),
    ]
    info = updater.background_result(timeout=3.0)
    if info is None:
        checks.append(("info", "Updates", "check disabled"))
    elif info.error:
        checks.append(("info", "Updates", "could not check (offline?)"))
    elif info.available:
        checks.append(("warn", "Updates", f"NEW VERSION {info.latest_version or info.latest_commit[:7]} AVAILABLE"))
    else:
        checks.append(("ok", "Updates", f"up to date ({info.current_version})"))
    boot_sequence(checks, animate=state.animate)
    notice = updater.pop_post_update_notice()
    if notice:
        update_views.render_post_update(notice)
    if info is not None and info.available:
        update_views.render_available(info)


def _state_from_args(args) -> SessionState:
    options = ScanOptions()
    if getattr(args, "command", None) == "scan":
        options = ScanOptions(
            offline=args.offline, compliance=args.compliance is not None,
            frameworks=[p.strip() for p in (args.compliance or "all").split(",") if p.strip()],
            max_file_size=max(1, args.max_file_size) * 1024, exclude=args.exclude, include_tests=not args.no_tests,
            jobs=max(0, args.jobs), private=list(args.private), no_registry=args.no_registry,
            check_confusion=args.check_confusion, ca_bundle=args.ca_bundle, cache=not args.no_cache,
            max_registry=max(0, args.max_registry), max_graph=max(0, args.max_graph), max_enrich=max(0, args.max_enrich),
            baseline=args.baseline, since=args.since, enrich=not args.no_enrich, auditor=args.auditor, output_dir=args.output or triage.default_output_dir(),
            min_confidence=args.min_confidence, learning=not args.no_learning, resolve_versions=not args.no_resolve,
            semantic=args.engine == "layered",
            trust_repo_config=True if args.trust_repo_config else (False if args.ignore_repo_config else None))
    elif getattr(args, "command", None) == "gui":
        options = ScanOptions(offline=args.offline, output_dir=args.output or triage.default_output_dir())
    interactive = console.is_terminal and sys.stdin is not None and sys.stdin.isatty()
    no_anim = getattr(args, "root_no_anim", False) or getattr(args, "no_anim", False) or bool(os.environ.get("CI"))
    return SessionState(options=options, animate=interactive and not no_anim,
                        plain=getattr(args, "plain", False), assume_yes=getattr(args, "yes", False))


def _apply_token_options(args, target: Target) -> bool:
    """--token-env / --ask-token for private https repositories. Returns False on a usage error."""
    if target.kind != "remote":
        return True
    if args.token_env:
        token = os.environ.get(args.token_env, "")
        if not token:
            say(f"Environment variable {args.token_env} is empty or not set.", "error")
            return False
        target.credentials = gitops.GitCredentials(token, os.environ.get("SECURE_REPO_GIT_USERNAME", ""))
    elif args.ask_token:
        from rich.prompt import Prompt

        token = Prompt.ask(Text("[?] Access token (input hidden)", style="bold white"), console=console,
                           password=True, default="", show_default=False).strip()
        if token:
            target.credentials = gitops.GitCredentials(token)
    return True


def _check_ci_options(args) -> str:
    """Validate the options that point at files or Git references before any scanning starts."""
    from secure_repo.core import netio
    from secure_repo.core.scanner import load_baseline

    if args.baseline:
        try:
            load_baseline(args.baseline)
        except ValueError as exc:
            return str(exc)
    if args.since:
        try:
            gitops.validate_ref(args.since)
        except gitops.GitError as exc:
            return str(exc)
    bundle = args.ca_bundle or netio.ca_bundle_path()
    if args.ca_bundle:
        try:
            netio.validate_ca_bundle(bundle)
        except netio.NetworkError as exc:
            return str(exc)
    return ""


def cmd_scan(args, state: SessionState) -> int:
    problem = _check_ci_options(args)
    if problem:
        say(problem, "error")
        return 2
    if args.compliance is not None and not compliance.resolve_frameworks(state.options.frameworks):
        say(f"Unknown framework list '{args.compliance}'. Available: {', '.join(compliance.FRAMEWORKS)}", "error")
        return 2
    if not state.plain:
        show_banner(state.animate)
        _boot(state)
    target = Target.parse(args.target, args.branch)
    if target.kind == "local" and not os.path.isdir(target.location):
        say(f"Directory not found: {target.location}", "error")
        return 1
    if not confirm_authorization(target, state):
        return 1
    if not _apply_token_options(args, target):
        return 2
    interactive = console.is_terminal and sys.stdin.isatty()
    if args.branch:
        try:
            gitops.validate_branch(args.branch)
            if target.kind == "remote":
                discover_with_auth(target, state)  # validates access (asks for a token if needed) before cloning
        except gitops.GitAuthError as exc:
            say(f"Access denied: {exc}", "error")
            return 1
        except gitops.GitError as exc:
            say(str(exc), "error")
            return 2
    elif interactive:
        ok, branch = choose_branch(target, state)
        if not ok:
            return 1
        target.branch = branch
    report, report_dir = run_scan(target, state)
    if report is None:
        return 1
    if args.open and report_dir:
        open_path(os.path.join(report_dir, "report.html"))
    if interactive and not args.no_menu and not state.plain:
        post_scan_menu(report, report_dir, state)
    update_views.render_compact(updater.background_result(timeout=0.5))
    if args.fail_on:
        threshold = SEVERITY_RANK[args.fail_on]
        # Only findings that still count: not false positives / filtered / disabled, not accepted risks, and - with
        # --baseline - only those that were not already in the baseline.
        failing = [f for f in report["findings"] if SEVERITY_RANK[f["severity"]] <= threshold
                   and f["status"] not in SUPPRESSED_STATUSES + ("accepted_risk",)
                   and (f.get("extra") or {}).get("baseline") != "existing"]
        if failing:
            scope = " new" if args.baseline else ""
            say(f"{len(failing)}{scope} finding(s) at or above '{args.fail_on}' - exiting with code 3 (--fail-on).", "error")
            return 3
    return 0


def cmd_branches(args, state: SessionState) -> int:
    target = Target.parse(args.target)
    if not _apply_token_options(args, target):
        return 2
    try:
        branches = discover_with_auth(target, state)
    except gitops.GitAuthError as exc:
        say(f"Access denied: {exc}", "error")
        return 1
    except gitops.GitError as exc:
        say(f"Branch discovery failed: {exc}", "error")
        return 1
    if not branches:
        say("No branches found (not a Git repository?).", "warn")
        return 1
    table = Table(box=box.SIMPLE_HEAVY, header_style=f"bold {CYAN}", title=Text(target.location, style=f"bold {NEON}"))
    table.add_column("#", justify="right", style=f"bold {NEON}")
    table.add_column("Branch", style="bold white")
    table.add_column("Type", style=DIM)
    table.add_column("Commit", style="grey62")
    table.add_column("Date", style=DIM)
    table.add_column("", style=VIOLET)
    for index, branch in enumerate(branches, 1):
        marker = "current" if branch.current else ("default" if branch.default else "")
        table.add_row(str(index), branch.name, "remote" if branch.remote else "local", branch.commit, branch.date, marker)
    console.print(table)
    return 0


def cmd_frameworks() -> int:
    table = Table(box=box.SIMPLE_HEAVY, header_style=f"bold {VIOLET}")
    table.add_column("ID", style=f"bold {NEON}")
    table.add_column("Framework", style="bold white")
    table.add_column("Version", style=DIM)
    table.add_column("Controls", justify="right")
    table.add_column("Scope", overflow="fold", style=DIM)
    for fw in compliance.list_frameworks():
        table.add_row(fw["id"], fw["name"], fw["version"], str(fw["controls"]), fw["description"])
    console.print(table)
    console.print(Text("usage: secure-repo scan . --compliance owasp,pci-dss   (or --compliance for all)", style=DIM))
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    state = _state_from_args(args)
    if args.command in (None, "scan", "gui") and not args.no_update_check:
        updater.start_background_check()
    try:
        if args.command is None:
            if not (console.is_terminal and sys.stdin.isatty()):
                parser.print_help()
                return 0
            show_banner(state.animate)
            _boot(state)
            return main_menu(state)
        if args.command == "scan":
            return cmd_scan(args, state)
        if args.command == "branches":
            return cmd_branches(args, state)
        if args.command == "gui":
            from secure_repo.gui.server import serve

            show_banner(False)
            serve(state.options, port=args.port, open_browser=not args.no_browser)
            return 0
        if args.command == "rules":
            section(f"DETECTION RULES ({len(RULES)})", NEON)
            views.render_rules(RULES, args.search)
            return 0
        if args.command == "frameworks":
            return cmd_frameworks()
        if args.command == "update":
            return update_views.cmd_update(args)
        if args.command == "triage":
            from secure_repo.cli.learning import cmd_triage

            return cmd_triage(args, parser)
        if args.command == "benchmark":
            from secure_repo.cli.learning import cmd_benchmark

            return cmd_benchmark(args)
        if args.command == "init-config":
            from secure_repo.cli.learning import cmd_init_config

            return cmd_init_config(args)
    except KeyboardInterrupt:
        console.print()
        say("Aborted by user.", "warn")
        return 130
    except EOFError:
        console.print()
        say("Input was closed before an answer was given. For unattended runs pass --branch and --yes.", "error")
        return 1
    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
