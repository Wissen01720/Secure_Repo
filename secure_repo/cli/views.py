"""Result views printed after a scan (and from the post-scan menu)."""

from __future__ import annotations

import os
from typing import Dict, List, Optional

from rich import box
from rich.columns import Columns
from rich.console import Group
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from secure_repo.cli.banner import big_status, section
from secure_repo.cli.theme import (CYAN, DIM, MAGENTA, NEON, SEVERITY_STYLE, SEVERITY_TAG, STATUS_STYLE, VIOLET,
                                   bar, console, sev_badge)
from secure_repo.core.models import OWASP_TOP10, SEVERITIES, SEVERITY_DESCRIPTIONS

GRADE_COLOR = {"A": NEON, "B": "#7ee787", "C": "#ffd23f", "D": "#ff8a00", "F": "#ff2e63"}


def _where(finding: Dict) -> str:
    if finding["file"] in ("", "."):
        return "(repository)"
    return finding["file"] + (f":{finding['line']}" if finding.get("line") else "")


def _human(size: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024:
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def render_summary(report: Dict, report_dir: Optional[str]) -> None:
    summary, meta, deps = report["summary"], report["meta"], report["dependency_summary"]
    counts = summary["by_severity"]
    section("MISSION REPORT")
    if counts["critical"]:
        big_status(False, f"CRITICAL EXPOSURE DETECTED\n{counts['critical']} critical and {counts['high']} high "
                          f"severity findings require immediate action.")
    elif counts["high"]:
        big_status(False, f"HIGH RISK FINDINGS\n{counts['high']} high severity findings detected.")
    else:
        big_status(True, "NO CRITICAL OR HIGH RISK FINDINGS\nKeep monitoring - security is a process.")

    grade_color = GRADE_COLOR.get(summary["grade"], "white")
    score = Text()
    score.append("SECURITY SCORE  ", style="bold white")
    score.append(bar(summary["score"] / 100, 40, grade_color))
    score.append(f"  {summary['score']:>3}/100  ", style=f"bold {grade_color}")
    score.append(f" GRADE {summary['grade']} ", style=f"bold black on {grade_color}")

    histogram = Table.grid(padding=(0, 2))
    histogram.add_column(no_wrap=True)
    histogram.add_column(no_wrap=True)
    histogram.add_column(justify="right", no_wrap=True)
    histogram.add_column(style=DIM, overflow="ellipsis", no_wrap=True)
    peak = max(counts.values()) or 1
    for severity in SEVERITIES:
        color = SEVERITY_STYLE[severity].replace("bold ", "")
        histogram.add_row(sev_badge(severity), bar(counts[severity] / peak, 30, color),
                          Text(str(counts[severity]), style=SEVERITY_STYLE[severity]),
                          SEVERITY_DESCRIPTIONS[severity].split(".")[0])

    facts = Table.grid(padding=(0, 2))
    facts.add_column(style=DIM, no_wrap=True)
    facts.add_column(style="white")
    facts.add_row("Target", Text(meta["target"], style=CYAN))
    facts.add_row("Branch / commit", f"{meta.get('branch') or 'n/a'} @ {(meta.get('commit') or 'n/a')[:12]}")
    facts.add_row("Mode", meta["mode"])
    facts.add_row("Files", f"{summary['files_total']} total · {summary['files_scanned']} analyzed · {summary['lines']:,} lines")
    facts.add_row("Libraries", f"{deps['total']} ({deps['direct']} direct / {deps['transitive']} transitive) · "
                               f"{deps['vulnerable']} vulnerable · {deps['vulnerabilities']} advisories")
    facts.add_row("Intelligence", "online (OSV.dev + deps.dev)" if deps["online"] else "offline / unavailable")
    facts.add_row("Duration", f"{meta['duration_seconds']} s")
    console.print(Panel(Group(score, Text(""), histogram, Text(""), facts),
                        title=Text(" SECURITY POSTURE ", style=f"bold {NEON}"), border_style=grade_color,
                        box=box.HEAVY, padding=(1, 2)))

    if summary["by_owasp"]:
        owasp = Table(box=box.SIMPLE_HEAD, header_style=f"bold {VIOLET}", expand=False)
        owasp.add_column("OWASP Top 10 (2021)")
        owasp.add_column("Findings", justify="right")
        owasp.add_column("")
        top = max(summary["by_owasp"].values())
        for code, count in summary["by_owasp"].items():
            owasp.add_row(f"{code if code != 'OTHER' else '---'}  {OWASP_TOP10[code]['name']}", str(count),
                          bar(count / top, 20, VIOLET))
        console.print(owasp)

    render_quality(report)
    active = [f for f in report["findings"] if f.get("status") not in ("false_positive", "filtered")]
    render_findings_table(active, limit=15, title="TOP FINDINGS")
    render_dependencies(report, only_vulnerable=True, limit=12)
    if report["compliance"].get("enabled"):
        render_compliance(report)
    render_structure_boxes(report["structure"])
    if report_dir:
        render_output_tree(report_dir)


def render_findings_table(findings: List[Dict], limit: Optional[int] = None, title: str = "FINDINGS") -> None:
    section(title, MAGENTA)
    if not findings:
        console.print(Text("  No findings for this selection.", style=DIM))
        return
    table = Table(box=box.SIMPLE_HEAVY, header_style=f"bold {CYAN}", expand=True, show_lines=False)
    table.add_column("ID", no_wrap=True, style="grey62")
    table.add_column("SEV", no_wrap=True)
    table.add_column("Weakness", ratio=3, overflow="fold")
    table.add_column("Location", ratio=3, overflow="fold", style=CYAN)
    table.add_column("Conf.", no_wrap=True)
    table.add_column("CWE", no_wrap=True, style=DIM)
    for finding in findings[:limit] if limit else findings:
        title = Text(finding["title"], style="white")
        if finding.get("in_test"):
            title.append(" (test)", style=DIM)
        if finding.get("engine") == "taint":
            title.append(" ⇢ data flow", style=f"bold {MAGENTA}")
        status = finding.get("status", "open")
        if status != "open":
            title.append(f" [{status.replace('_', ' ')}]", style=NEON if status == "false_positive" else "#ffd23f")
        conf = finding.get("confidence", "medium")
        conf_style = {"high": NEON, "medium": "#ffd23f", "low": "grey50"}.get(conf, "white")
        table.add_row(finding["id"], sev_badge(finding["severity"]), title, escape(_where(finding)),
                      Text(f"{ {'high': 'HIGH', 'medium': 'MED', 'low': 'LOW'}.get(conf, conf)} "
                           f"{finding.get('confidence_score', '')}", style=conf_style),
                      finding.get("cwe") or "-")
    console.print(table)
    if limit and len(findings) > limit:
        console.print(Text(f"  ... {len(findings) - limit} more findings in the report folder "
                           f"(or use the post-scan menu to browse them).", style=DIM))


def render_finding_detail(report: Dict, finding: Dict, root: Optional[str] = None) -> None:
    rule = report["rules"].get(finding["rule_id"], {})
    style = SEVERITY_STYLE[finding["severity"]]
    header = Text()
    header.append(f"{finding['id']}  ", style="grey62")
    header.append(f" {finding['severity'].upper()} ", style=style + " reverse")
    header.append(f"  {finding['title']}", style="bold white")
    meta = Table.grid(padding=(0, 2))
    meta.add_column(style=DIM)
    meta.add_column()
    meta.add_row("Location", Text(_where(finding), style=CYAN))
    meta.add_row("Rule", f"{finding['rule_id']} · {finding['category']} · engine {finding.get('engine', 'pattern')}")
    reasons = (finding.get("extra") or {}).get("confidence_reasons") or []
    meta.add_row("Confidence", f"{finding['confidence']} ({finding.get('confidence_score', '-')}/100)"
                               + (f" · {'; '.join(reasons)}" if reasons else ""))
    if finding.get("status", "open") != "open":
        triage_info = finding.get("triage") or {}
        meta.add_row("Status", Text(f"{finding['status']} - {triage_info.get('reason', '')}", style=NEON))
    meta.add_row("Standards", f"{finding.get('cwe') or '-'} · OWASP {finding.get('owasp') or '-'} "
                              f"{OWASP_TOP10.get(finding.get('owasp') or '', {}).get('name', '')}")
    parts = [header, Text(""), meta]
    if finding.get("snippet"):
        parts += [Text(""), Panel(Text(finding["snippet"], style="#e6edf3"), title="evidence (secrets redacted)",
                                  title_align="left", border_style="grey30", box=box.SQUARE)]
    if finding.get("detail"):
        parts += [Text(""), Text.assemble(("DETAIL  ", f"bold {CYAN}"), (finding["detail"], "white"))]
    if finding.get("flow"):
        flow = Table.grid(padding=(0, 1))
        flow.add_column(no_wrap=True)
        flow.add_column(no_wrap=True, style="grey62")
        flow.add_column(style=CYAN)
        flow.add_column(overflow="fold", style="#e6edf3")
        steps = finding["flow"]
        for index, step in enumerate(steps):
            marker = "◉" if index == 0 else ("✖" if index == len(steps) - 1 else "│")
            color = NEON if index == 0 else ("#ff2e63" if index == len(steps) - 1 else "grey50")
            flow.add_row(Text(marker, style=f"bold {color}"), f"L{step['line']}", step["label"], step.get("code", ""))
        parts += [Text(""), Text("DATA FLOW  (untrusted source → sink)", style=f"bold {MAGENTA}"), flow]
    if rule:
        parts += [Text(""), Text("WHY IS THIS INSECURE?", style=f"bold {MAGENTA}"), Text(rule["description"]),
                  Text(""), Text("HOW TO FIX", style=f"bold {NEON}"), Text(rule["recommendation"])]
        if rule.get("references"):
            parts += [Text(""), Text("REFERENCES", style=f"bold {VIOLET}")] + [
                Text(f"  → {ref}", style=DIM) for ref in rule["references"]]
    vulns = finding.get("extra", {}).get("vulnerabilities") or []
    if vulns:
        table = Table(box=box.SIMPLE, header_style=f"bold {CYAN}")
        table.add_column("Advisory")
        table.add_column("Severity")
        table.add_column("Fixed in")
        table.add_column("Summary", overflow="fold")
        for vuln in vulns[:20]:
            table.add_row(vuln["id"], sev_badge(vuln["severity"]), ", ".join(vuln["fixed"]) or "-", vuln["summary"])
        parts += [Text(""), table]
    console.print(Panel(Group(*parts), border_style=style.replace("bold ", ""), box=box.ROUNDED, padding=(1, 2)))


def render_dependencies(report: Dict, only_vulnerable: bool = False, limit: Optional[int] = None) -> None:
    deps = report["dependencies"]
    summary = report["dependency_summary"]
    section("LIBRARIES & SUPPLY CHAIN", CYAN)
    eco = "  ".join(f"{name}:{count}" for name, count in summary["ecosystems"].items()) or "none detected"
    console.print(Text.assemble(("  ecosystems ", DIM), (eco, CYAN), ("   manifests ", DIM),
                                (str(len(summary["manifests"])), "white"), ("   vulnerable ", DIM),
                                (str(summary["vulnerable"]), SEVERITY_STYLE["high"] if summary["vulnerable"] else NEON)))
    rows = [d for d in deps if d["vulnerabilities"] or d["issues"]] if only_vulnerable else deps
    if not rows:
        console.print(Text("  No vulnerable or risky libraries detected." if only_vulnerable else
                           "  No dependencies detected.", style=NEON if only_vulnerable else DIM))
        return
    table = Table(box=box.SIMPLE_HEAVY, header_style=f"bold {CYAN}", expand=True)
    table.add_column("Library", overflow="fold", ratio=3)
    table.add_column("Version", no_wrap=True)
    table.add_column("Ecosystem", no_wrap=True, style=DIM)
    table.add_column("Type", no_wrap=True, style=DIM)
    table.add_column("Risk", no_wrap=True)
    table.add_column("Advisories / issues", overflow="fold", ratio=4)
    table.add_column("Resolved by", no_wrap=True, style=VIOLET)
    table.add_column("Latest", no_wrap=True, style=DIM)
    for dep in rows[:limit] if limit else rows:
        risk = sev_badge(dep["max_severity"]) if dep["max_severity"] else (
            Text("[WARN]", style="#ffd23f") if dep["issues"] else Text("[ OK ]", style=NEON))
        notes = ", ".join(v["id"] for v in dep["vulnerabilities"][:4])
        if len(dep["vulnerabilities"]) > 4:
            notes += f" +{len(dep['vulnerabilities']) - 4}"
        if dep["issues"]:
            notes = (notes + " | " if notes else "") + "; ".join(dep["issues"][:2])
        table.add_row(escape(dep["name"]), escape(dep["version"] or dep["spec"] or "*"), dep["ecosystem"],
                      "direct" if dep["direct"] else "transitive", risk, escape(notes or "-"),
                      dep.get("resolved_by") or ("unresolved" if dep["source"] == "registry" else dep["source"]),
                      dep["latest"] or "-")
    console.print(table)
    if limit and len(rows) > limit:
        console.print(Text(f"  ... {len(rows) - limit} more - see dependencies/inventory.csv", style=DIM))


def render_compliance(report: Dict, detailed: bool = False) -> None:
    section("COMPLIANCE AUDIT", VIOLET)
    table = Table(box=box.SIMPLE_HEAVY, header_style=f"bold {VIOLET}", expand=True)
    table.add_column("Framework", ratio=3)
    table.add_column("Score", ratio=3)
    table.add_column("PASS", justify="right", style=STATUS_STYLE["pass"])
    table.add_column("WARN", justify="right", style=STATUS_STYLE["warning"])
    table.add_column("FAIL", justify="right", style=STATUS_STYLE["fail"])
    table.add_column("MANUAL", justify="right", style=STATUS_STYLE["manual"])
    for fw in report["compliance"]["frameworks"]:
        color = NEON if fw["score"] >= 80 else "#ffd23f" if fw["score"] >= 50 else "#ff2e63"
        s = fw["summary"]
        table.add_row(f"{fw['name']} [dim]{fw['version']}[/dim]", bar(fw["score"] / 100, 18, color) +
                      Text(f" {fw['score']:3d}%", style=f"bold {color}"), str(s["pass"]), str(s["warning"]),
                      str(s["fail"]), str(s["manual"]))
    console.print(table)
    if detailed:
        for fw in report["compliance"]["frameworks"]:
            controls = Table(box=box.MINIMAL, header_style=f"bold {CYAN}", expand=True,
                             title=Text(f"{fw['name']} {fw['version']}", style=f"bold {VIOLET}"), title_justify="left")
            controls.add_column("Status", no_wrap=True)
            controls.add_column("Control", no_wrap=True, style="white")
            controls.add_column("Title / evidence", overflow="fold", ratio=5)
            for control in fw["controls"]:
                evidence = Text(control["title"], style="white")
                for line in control["evidence"][:3]:
                    evidence.append("\n  · " + line, style=DIM)
                controls.add_row(Text(control["status"].upper(), style=STATUS_STYLE[control["status"]]),
                                 control["id"], evidence)
            console.print(controls)
    console.print(Text("  " + report["compliance"]["disclaimer"], style="italic grey50"))


def render_structure_boxes(tree: Dict, max_boxes: int = 12) -> None:
    section("REPOSITORY STRUCTURE MAP", CYAN)
    children = tree.get("children", [])
    dirs = [c for c in children if c["type"] == "dir"]
    files = [c for c in children if c["type"] == "file"]
    panels = []
    for node in dirs[:max_boxes]:
        color = SEVERITY_STYLE.get(node["risk"], "grey35").replace("bold ", "") if node["risk"] else NEON
        body = Text(no_wrap=True, overflow="ellipsis")
        body.append(f"{node['files']} files · {_human(node['size'])}\n", style=DIM)
        for sub in node.get("children", [])[:4]:
            icon = "▣ " if sub["type"] == "dir" else "· "
            name = sub["name"] + ("/" if sub["type"] == "dir" else "")
            body.append(icon + (name if len(name) <= 20 else name[:19] + "…"), style="white" if sub["risk"] else "grey62")
            if sub["findings"]:
                body.append(f" ▲{sub['findings']}", style=SEVERITY_STYLE[sub["risk"]])
            body.append("\n")
        if len(node.get("children", [])) > 4:
            body.append(f"  +{len(node['children']) - 4} more\n", style="grey42")
        sev_line = " ".join(f"{node['severity'][s]}{SEVERITY_TAG[s].strip()[0]}" for s in SEVERITIES if node["severity"].get(s))
        body.append(sev_line or "clean", style=SEVERITY_STYLE.get(node["risk"], NEON) if node["risk"] else NEON)
        panels.append(Panel(body, title=Text(f"▣ {node['name']}/"[:24], style="bold white"), title_align="left",
                            border_style=color, box=box.SQUARE, width=30, padding=(0, 1)))
    if files:
        risky = [f for f in files if f["findings"]]
        body = Text(no_wrap=True, overflow="ellipsis")
        body.append(f"{len(files)} files at the root\n", style=DIM)
        for leaf in (risky or files)[:5]:
            body.append("· " + leaf["name"][:22], style="white" if leaf["findings"] else "grey62")
            if leaf["findings"]:
                body.append(f" ▲{leaf['findings']}", style=SEVERITY_STYLE[leaf["risk"]])
            body.append("\n")
        worst = next((s for s in SEVERITIES if any(f["risk"] == s for f in files)), None)
        panels.append(Panel(body, title=Text("▣ (root files)", style="bold white"), title_align="left",
                            border_style=SEVERITY_STYLE.get(worst, NEON).replace("bold ", ""), box=box.SQUARE,
                            width=30, padding=(0, 1)))
    if len(dirs) > max_boxes:
        panels.append(Panel(Text(f"+{len(dirs) - max_boxes} more directories", style=DIM), box=box.SQUARE,
                            border_style="grey30", width=30))
    if panels:
        console.print(Columns(panels, padding=(0, 1)))
    legend = Text("  border color = worst severity inside the box · ▲ = findings", style=DIM)
    console.print(legend)


def render_structure_tree(tree: Dict, max_depth: int = 4, max_children: int = 14) -> None:
    section("REPOSITORY TREE", CYAN)

    def label(node: Dict) -> Text:
        is_dir = node["type"] == "dir"
        text = Text(("▣ " if is_dir else "· ") + node["name"] + ("/" if is_dir else ""),
                    style=("bold " if is_dir else "") + ("white" if node["findings"] else "grey62"))
        if node["findings"]:
            text.append("  ")
            for severity in SEVERITIES:
                if node["severity"].get(severity):
                    text.append(f"{SEVERITY_TAG[severity].strip()}:{node['severity'][severity]} ",
                                style=SEVERITY_STYLE[severity])
        return text

    root = Tree(Text(f"{tree['name']}/  ({tree['files']} files, {tree['lines']:,} lines)", style=f"bold {NEON}"),
                guide_style="grey30")

    def walk(node: Dict, branch: Tree, depth: int) -> None:
        children = node.get("children", [])
        for child in children[:max_children]:
            sub = branch.add(label(child))
            if child["type"] == "dir" and depth < max_depth:
                walk(child, sub, depth + 1)
        if len(children) > max_children:
            branch.add(Text(f"... {len(children) - max_children} more", style="grey42"))

    walk(tree, root, 1)
    console.print(root)


def render_output_tree(report_dir: str) -> None:
    section("EVIDENCE LOCKER", NEON)
    root = Tree(Text(report_dir, style=f"bold {NEON}"), guide_style="grey30")
    nodes = {report_dir: root}
    for current, dirs, files in os.walk(report_dir):
        dirs.sort()
        parent = nodes[current]
        for directory in dirs:
            nodes[os.path.join(current, directory)] = parent.add(Text(directory + "/", style=f"bold {CYAN}"))
        shown = sorted(files)
        for name in shown[:12]:
            parent.add(Text(name, style="white"))
        if len(shown) > 12:
            parent.add(Text(f"... {len(shown) - 12} more", style="grey42"))
    console.print(root)
    console.print(Text.assemble(("  open ", DIM), ("report.html", f"bold {NEON}"),
                                (" in a browser for the interactive neural map and structure boxes.", DIM)))


def render_rules(rules: List, search: str = "") -> None:
    table = Table(box=box.SIMPLE_HEAVY, header_style=f"bold {CYAN}", expand=True)
    table.add_column("Rule", no_wrap=True, style="grey62")
    table.add_column("SEV", no_wrap=True)
    table.add_column("Title", ratio=3)
    table.add_column("Category", ratio=2, style=DIM)
    table.add_column("CWE / OWASP", no_wrap=True, style=DIM)
    table.add_column("Languages", ratio=3, overflow="fold", style=DIM)
    for rule in rules:
        haystack = f"{rule.id} {rule.title} {rule.category} {' '.join(rule.languages)} {rule.cwe}".lower()
        if search and search.lower() not in haystack:
            continue
        languages = "path-based" if rule.path else ("all text files" if "*" in rule.languages else ", ".join(rule.languages))
        if not rule.pattern and not rule.path:
            languages = "built-in analyzer"
        table.add_row(rule.id, sev_badge(rule.severity), rule.title, rule.category, f"{rule.cwe or '-'} / {rule.owasp}",
                      languages)
    console.print(table)


def render_quality(report: Dict, detailed: bool = False) -> None:
    analysis = report.get("analysis") or {}
    if not analysis:
        return
    summary = report["summary"]
    section("ANALYSIS QUALITY", NEON)
    engines = summary.get("by_engine") or {}
    grid = Table.grid(padding=(0, 3))
    grid.add_column(style=DIM, no_wrap=True)
    grid.add_column()
    grid.add_row("Findings by engine", Text("  ".join(f"{k}:{v}" for k, v in engines.items()) or "-", style=CYAN))
    grid.add_row("Noise discarded", Text(f"{analysis.get('noise_total', 0)} matches (comments, strings, constant "
                                         f"arguments, safe APIs, non-security context)", style=NEON))
    knowledge = analysis.get("knowledge") or {}
    grid.add_row("Suppressed", Text(f"{summary.get('suppressed', 0)} finding(s) - {knowledge.get('decisions', 0)} triage "
                                    f"decisions, {knowledge.get('learned_patterns', 0)} learned patterns, "
                                    f"{knowledge.get('allowlisted', 0)} allow-listed, "
                                    f"{knowledge.get('below_min_confidence', 0)} below min confidence", style="white"))
    grid.add_row("Learning", Text("ON (secure-repo triage stats)" if analysis.get("learning") else "OFF", style=VIOLET))
    grid.add_row("Configuration", Text(analysis.get("config") or "none - run 'secure-repo init-config'", style="white"))
    console.print(grid)
    if detailed:
        noise = analysis.get("noise_filtered") or {}
        if noise:
            table = Table(box=box.SIMPLE, header_style=f"bold {CYAN}")
            table.add_column("Discarded because")
            table.add_column("Matches", justify="right")
            for reason, count in noise.items():
                table.add_row(reason, str(count))
            console.print(table)
        suppressed = [f for f in report["findings"] if f.get("status") in ("false_positive", "filtered")]
        if suppressed:
            table = Table(box=box.SIMPLE, header_style=f"bold {CYAN}", title=Text("Suppressed findings", style=NEON))
            table.add_column("ID", style="grey62")
            table.add_column("Rule")
            table.add_column("Location", style=CYAN, overflow="fold")
            table.add_column("Status")
            table.add_column("Reason", overflow="fold", style=DIM)
            for f in suppressed:
                table.add_row(f["id"], f["rule_id"], escape(_where(f)), f["status"], (f.get("triage") or {}).get("reason", ""))
            console.print(table)


def render_lockfile(report: Dict) -> None:
    lock = report.get("lockfile") or {}
    resolution = report["dependency_summary"].get("resolution") or {}
    section("VIRTUAL LOCKFILE", VIOLET)
    console.print(Text("  resolution: " + ("  ".join(f"{k}:{v}" for k, v in resolution.items()) or "-"), style=DIM))
    if not lock.get("manifests") and not lock.get("unresolved"):
        console.print(Text("  Every dependency is pinned by a manifest or lockfile.", style=NEON))
        return
    for entry in lock.get("manifests", []):
        table = Table(box=box.SIMPLE_HEAVY, header_style=f"bold {CYAN}", expand=True,
                      title=Text(f"{entry['manifest']} ({entry['ecosystem']})", style=f"bold {VIOLET}"),
                      title_justify="left")
        table.add_column("Package", overflow="fold")
        table.add_column("Declared", style=DIM)
        table.add_column("Resolved", style=f"bold {NEON}")
        table.add_column("How", style=VIOLET)
        table.add_column("Vulnerable")
        direct = [p for p in entry["packages"] if p["direct"]]
        for p in direct[:40]:
            table.add_row(escape(p["name"]), escape(p["declared"]), p["resolved"], p["resolved_by"],
                          Text("YES", style="bold #ff2e63") if p["vulnerable"] else Text("no", style=NEON))
        console.print(table)
        transitive = len(entry["packages"]) - len(direct)
        if transitive:
            console.print(Text(f"  + {transitive} transitive packages resolved through the dependency graph", style=DIM))
        console.print(Text("  create a real lockfile: " + " | ".join(entry["commands"][:2]), style=CYAN))
    for item in lock.get("unresolved", []):
        console.print(Text(f"  [!] unresolved: {item['name']} {item['declared']} ({item['manifest']})", style="#ffd23f"))
    console.print(Text("  full guide: dependencies/lockfile-guide.md", style=DIM))
