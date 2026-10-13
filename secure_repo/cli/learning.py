"""CLI for the learning loop: triage, knowledge base, benchmark and project configuration."""

from __future__ import annotations

import json
import os
from typing import Dict, Optional, Tuple

from rich import box
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

from secure_repo.cli.banner import section
from secure_repo.cli.theme import CYAN, DIM, MAGENTA, NEON, VIOLET, bar, console, say, sev_badge
from secure_repo.core import benchmark, review
from secure_repo.core.config import write_template
from secure_repo.core.triage import REPO_TRIAGE_FILE, KnowledgeBase, data_dir, project_key

STATUS_LABEL = {"f": "false_positive", "a": "accepted_risk", "c": "confirmed", "o": "open"}
STATUS_STYLE = {"open": "white", "confirmed": f"bold {MAGENTA}", "accepted_risk": "bold #ffd23f",
                "false_positive": f"bold {NEON}", "filtered": "grey50",
                "disabled_by_config": "grey50", "suppressed_inline": "grey50"}


def _load_report(path: str) -> Tuple[Dict, str]:
    folder = path if os.path.isdir(path) else os.path.dirname(os.path.abspath(path))
    with open(os.path.join(folder, "report.json"), encoding="utf-8") as handle:
        return json.load(handle), folder


# ---------------------------------------------------------------------- interactive triage
def interactive_triage(report: Dict, report_dir: Optional[str]) -> None:
    """Loop used by the post-scan menu: mark findings and watch the score/report update."""
    knowledge = KnowledgeBase()
    section("TRIAGE - TEACH SECURE REPO", NEON)
    console.print(Text("Mark findings as confirmed, accepted risk or false positive. False positives can be "
                       "generalized to the same code pattern so they never come back. Every decision is kept in the "
                       f"audit trail and in your knowledge base ({data_dir()}).", style=DIM))
    by_id = {f["id"]: f for f in report["findings"]}
    while True:
        answer = Prompt.ask(Text.assemble(("[?] ", f"bold {VIOLET}"),
                                          ("Finding ID(s) to triage (e.g. SR-0004 SR-0009), 'q' to finish", "bold white")),
                            console=console, default="q").strip()
        if answer.lower() in ("q", "quit", "0", ""):
            return
        ids = [token.upper() for token in answer.replace(",", " ").split()]
        missing = [i for i in ids if i not in by_id]
        if missing:
            say(f"Unknown finding(s): {', '.join(missing)}", "warn")
            continue
        for finding_id in ids:
            finding = by_id[finding_id]
            console.print(Text.assemble(("  ", ""), sev_badge(finding["severity"]), (f" {finding_id} ", "grey62"),
                                        (finding["title"], "bold white"), ("  ", ""),
                                        (f"{finding['file']}:{finding['line']}", CYAN), ("  engine ", DIM),
                                        (finding.get("engine", "pattern"), "white"), ("  confidence ", DIM),
                                        (f"{finding.get('confidence')} ({finding.get('confidence_score')})", "white")))
            if finding.get("snippet"):
                console.print(Text(f"    {finding['snippet']}", style="#e6edf3"))
        choice = Prompt.ask(Text.assemble(("[?] ", f"bold {VIOLET}"),
                                          ("[f]alse positive · [a]ccept risk · [c]onfirmed · [o]pen again", "bold white")),
                            console=console, choices=list(STATUS_LABEL), show_choices=False, default="f")
        status = STATUS_LABEL[choice]
        reason = Prompt.ask(Text.assemble(("[?] ", f"bold {VIOLET}"), ("Reason / justification", "bold white")),
                            console=console, default="" if status != "false_positive" else None) or ""
        scope = "finding"
        if status == "false_positive":
            console.print(Text("  Scope: [1] only this finding  [2] this code pattern in this project  "
                               "[3] this code pattern in every project", style=DIM))
            scope = {"1": "finding", "2": "project-pattern", "3": "global-pattern"}[
                Prompt.ask(Text("  scope", style="bold white"), console=console, choices=["1", "2", "3"], default="1")]
        try:
            result = review.triage(report, ids, status, reason, scope, knowledge=knowledge, report_dir=report_dir)
        except ValueError as exc:
            say(str(exc), "error")
            continue
        extra = f" · {result['learned']} similar finding(s) suppressed automatically" if result["learned"] else ""
        say(f"{', '.join(result['changed'])} -> {status}{extra}. Score now {result['score']}/100 "
            f"(grade {result['grade']}){' · reports regenerated' if report_dir else ''}", "ok")


# ---------------------------------------------------------------------- commands
def _stats_table(knowledge: KnowledgeBase) -> None:
    rows = knowledge.stats()
    if not rows:
        say("No triage decisions yet. Triage findings from the post-scan menu, the GUI or 'secure-repo triage mark'.")
        return
    table = Table(box=box.SIMPLE_HEAVY, header_style=f"bold {CYAN}", title=Text("Rule precision from your triage",
                                                                                  style=f"bold {NEON}"))
    table.add_column("Rule", style="grey70")
    table.add_column("Confirmed", justify="right")
    table.add_column("Accepted", justify="right")
    table.add_column("False +", justify="right", style=NEON)
    table.add_column("Precision")
    table.add_column("Learned patterns", justify="right")
    table.add_column("Effect", style=DIM)
    for row in rows:
        color = NEON if row["precision"] >= 0.8 else "#ffd23f" if row["precision"] >= 0.4 else "#ff2e63"
        effect = "confidence -25 (noisy)" if row["feedback"] >= 3 and row["precision"] <= 0.4 else (
            "confidence +10 (reliable)" if row["feedback"] >= 3 and row["precision"] >= 0.9 else "-")
        table.add_row(row["rule_id"], str(row["confirmed"]), str(row["accepted_risk"]), str(row["false_positive"]),
                      bar(row["precision"], 14, color) + Text(f" {int(row['precision'] * 100)}%", style=color),
                      str(row["patterns"]), effect)
    console.print(table)


def cmd_triage(args, parser) -> int:
    knowledge = KnowledgeBase()
    action = getattr(args, "triage_command", None)
    if action in (None, "stats"):
        _stats_table(knowledge)
        console.print(Text(f"knowledge base: {knowledge.path}", style=DIM))
        return 0
    if action == "list":
        table = Table(box=box.SIMPLE, header_style=f"bold {CYAN}", expand=True)
        table.add_column("Fingerprint / id", style="grey62", no_wrap=True)
        table.add_column("Status")
        table.add_column("Rule", no_wrap=True)
        table.add_column("Where / pattern", overflow="fold", ratio=3)
        table.add_column("Reason", overflow="fold", ratio=2, style=DIM)
        table.add_column("Project", overflow="fold", ratio=2, style=DIM)
        for key, project in knowledge.data["projects"].items():
            for fp, decision in project["decisions"].items():
                if args.status and decision["status"] != args.status:
                    continue
                table.add_row(fp, Text(decision["status"], style=STATUS_STYLE.get(decision["status"], "white")),
                              decision["rule_id"], f"{decision.get('file')}:{decision.get('line')}",
                              decision.get("reason", ""), project.get("name", key))
        for pattern in knowledge.data["patterns"]:
            if args.status and args.status != "false_positive":
                continue
            table.add_row(pattern["id"], Text("learned pattern", style=f"bold {VIOLET}"), pattern["rule_id"],
                          pattern["shape"], pattern.get("reason", ""), "global" if not pattern.get("project") else pattern["project"])
        console.print(table)
        return 0
    if action == "mark":
        report, folder = _load_report(args.report)
        try:
            result = review.triage(report, args.ids, args.status, args.reason, args.scope, knowledge=knowledge,
                                   report_dir=folder)
        except ValueError as exc:
            say(str(exc), "error")
            return 2
        say(f"{', '.join(result['changed'])} -> {args.status}; score {result['score']}/100 ({result['grade']}); "
            f"{result['learned']} similar finding(s) suppressed; report regenerated in {folder}", "ok")
        return 0
    if action == "forget":
        if knowledge.forget(args.identifier):
            say(f"Removed {args.identifier}", "ok")
            return 0
        say(f"Nothing found for {args.identifier}", "warn")
        return 1
    if action == "export":
        if args.to_repo:
            from secure_repo.core.gitops import find_repo_root, remote_url

            root = find_repo_root(args.to_repo) or os.path.abspath(args.to_repo)
            key, _name = project_key({"remote": remote_url(root), "target": root, "name": os.path.basename(root)})
            target = os.path.join(root, REPO_TRIAGE_FILE)
            count = knowledge.export(target, key=key)
            say(f"{count} decision(s)/pattern(s) written to {target} - commit it to share the triage with your team.", "ok")
            return 0
        count = knowledge.export(args.file)
        say(f"Knowledge base exported to {os.path.abspath(args.file)} ({count} entries in the payload).", "ok")
        return 0
    if action == "import":
        count = knowledge.import_file(args.file)
        say(f"Imported {count} entr{'y' if count == 1 else 'ies'} into {knowledge.path}", "ok")
        return 0
    if action == "export-cases":
        directory = args.directory or os.path.join(data_dir(), "benchmark")
        count = knowledge.export_cases(directory)
        say(f"{count} false-positive case(s) written to {directory}. 'secure-repo benchmark' now includes them "
            f"(user cases in {os.path.join(data_dir(), 'benchmark')} are loaded automatically).", "ok")
        return 0
    if action == "reset":
        if not args.yes:
            say("This deletes every decision and learned pattern. Re-run with --yes to confirm.", "warn")
            return 1
        knowledge.reset()
        say("Knowledge base cleared.", "ok")
        return 0
    parser.print_help()
    return 2


def cmd_benchmark(args) -> int:
    section("DETECTION BENCHMARK", NEON)
    extra = list(args.cases)
    user_cases = os.path.join(data_dir(), "benchmark")
    if os.path.isdir(user_cases):
        extra.append(user_cases)
    modes = [("layered", True)] + ([("patterns (legacy)", False)] if args.compare else [])
    results = {name: benchmark.run(extra, args.rule, semantic) for name, semantic in modes}
    main = results["layered"]
    table = Table(box=box.SIMPLE_HEAVY, header_style=f"bold {CYAN}", expand=True)
    table.add_column("Rule", style="grey70", no_wrap=True)
    table.add_column("TP", justify="right", style=NEON)
    table.add_column("FP", justify="right", style="#ff2e63")
    table.add_column("FN", justify="right", style="#ffd23f")
    table.add_column("Precision")
    table.add_column("Recall")
    table.add_column("Notes", style=DIM, overflow="fold", ratio=2)
    for rule, score in main["rules"].items():
        table.add_row(rule, str(score["tp"]), str(score["fp"]), str(score["fn"]),
                      bar(score["precision"], 10) + Text(f" {int(score['precision'] * 100)}%"),
                      bar(score["recall"], 10, CYAN) + Text(f" {int(score['recall'] * 100)}%"),
                      "; ".join(score["samples"][:3]))
    console.print(table)
    summary = Table.grid(padding=(0, 3))
    for name, result in results.items():
        summary.add_row(Text(name, style="bold white"), Text(f"precision {int(result['precision'] * 100)}%", style=NEON),
                        Text(f"recall {int(result['recall'] * 100)}%", style=CYAN),
                        Text(f"TP {result['tp']} · FP {result['fp']} · FN {result['fn']}", style=DIM))
    console.print(Panel(summary, title=Text(" ENGINE QUALITY ", style=f"bold {NEON}"), border_style=NEON))
    console.print(Text(f"{len(main['cases'])} case files · add yours with --cases DIR or 'secure-repo triage "
                       "export-cases'", style=DIM))
    return 0 if main["fp"] == 0 and main["fn"] == 0 else 1


def cmd_init_config(args) -> int:
    from secure_repo.core.gitops import find_repo_root

    root = find_repo_root(args.path) or os.path.abspath(args.path)
    try:
        path = write_template(root)
    except FileExistsError as exc:
        say(f"{exc} already exists - edit it instead.", "warn")
        return 1
    say(f"Created {path}. Edit it to disable rules, allow-list paths/values, set a minimum confidence or add "
        f"custom rules; commit it so the whole team shares the tuning.", "ok")
    return 0
