"""Renderers for the individual report artifacts."""

from __future__ import annotations

import csv
import io
import uuid
from typing import Dict, List

from secure_repo.core.models import OWASP_TOP10, SEVERITIES, SEVERITY_DESCRIPTIONS, SUPPRESSED_STATUSES

SEVERITY_ICON = {"critical": "🟥", "high": "🟧", "medium": "🟨", "low": "🟦", "info": "⬜"}
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
SARIF_SCORE = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "0.0"}


def _md_escape(text: str) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ").replace("`", "'")


def _where(finding: Dict) -> str:
    if finding["file"] in ("", "."):
        return "(repository)"
    return finding["file"] + (f":{finding['line']}" if finding.get("line") else "")


def split_score_lines(summary: Dict) -> List[str]:
    """Production / tests / density, as a small table under the headline score."""
    scores = summary.get("scores")
    if not scores:
        return []
    density = scores["density"]
    per_kloc = "n/a" if density["per_kloc"] is None else f"{density['per_kloc']} per 1,000 lines"
    serious = "n/a" if density["serious_per_kloc"] is None else f"{density['serious_per_kloc']} per 1,000 lines"
    return ["| Score of | Value |", "|---|---|",
            f"| Production code | {scores['production']['score']}/100 (grade {scores['production']['grade']}) |",
            f"| Test code | {scores['tests']['score']}/100 (grade {scores['tests']['grade']}) |",
            f"| Findings in production code | {density['findings']} ({per_kloc}; {density['kloc']} KLOC analyzed) |",
            f"| Critical + high in production code | {density['serious']} ({serious}) |", ""]


def markdown_summary(report: Dict) -> str:
    meta, summary = report["meta"], report["summary"]
    dep = report["dependency_summary"]
    lines = [
        f"# Secure Repo security report - {meta['name']}",
        "",
        "| Field | Value |", "|---|---|",
        f"| Target | `{_md_escape(meta['target'])}` |",
        f"| Branch | `{meta.get('branch') or 'n/a'}` |",
        f"| Commit | `{meta.get('commit') or 'n/a'}` |",
        f"| Scan mode | {meta['mode']} |",
        f"| Started (UTC) | {meta['started_at']} |",
        f"| Duration | {meta['duration_seconds']} s |",
        f"| Auditor | {_md_escape(meta.get('auditor', ''))} |",
        f"| Tool | Secure Repo {report['tool']['version']} ({report['tool']['rules']} rules) |",
        "",
        f"## Security score: **{summary['score']}/100 (grade {summary['grade']})**",
        "",
    ] + ([f"> **{summary['grade_cap']['message']}**", ""] if summary.get("grade_cap") else []) + split_score_lines(summary) + [
        "| Severity | Findings | Meaning |", "|---|---:|---|",
    ]
    for sev in SEVERITIES:
        lines.append(f"| {SEVERITY_ICON[sev]} {sev.title()} | {summary['by_severity'][sev]} | {SEVERITY_DESCRIPTIONS[sev]} |")
    lines += [
        "",
        f"- Files: {summary['files_total']} total, {summary['files_scanned']} analyzed, {summary['lines']:,} lines",
        f"- Libraries: {dep['total']} ({dep['direct']} direct, {dep['transitive']} transitive) in "
        f"{len(dep['manifests'])} manifests - {dep['vulnerable']} vulnerable, {dep['vulnerabilities']} unique advisories",
        f"- Vulnerability intelligence: {'online (OSV.dev / deps.dev)' if dep['online'] else 'offline / unavailable'}",
        "",
        "## OWASP Top 10 (2021) distribution", "",
        "| Category | Findings |", "|---|---:|",
    ]
    for code, count in summary["by_owasp"].items():
        lines.append(f"| {code} - {OWASP_TOP10[code]['name']} | {count} |")
    lines += ["", "## Most affected files", "", "| File | Findings | Worst severity |", "|---|---:|---|"]
    for entry in summary["top_files"]:
        lines.append(f"| `{_md_escape(entry['file'] if entry['file'] != '.' else '(repository)')}` | {entry['count']} | {entry['risk']} |")
    analysis = report.get("analysis") or {}
    if analysis:
        engines = summary.get("by_engine", {})
        lines += ["", "## Analysis quality", "",
                  "- Findings by engine: " + (", ".join(f"{k} {v}" for k, v in engines.items()) or "none"),
                  f"- Noisy matches discarded automatically: {analysis.get('noise_total', 0)} (see quality.md)",
                  f"- Suppressed findings (false positives / filtered): {summary.get('suppressed', 0)}",
                  f"- Learning: {'on' if analysis.get('learning') else 'off'} - "
                  f"{(analysis.get('knowledge') or {}).get('decisions', 0)} triage decisions and "
                  f"{(analysis.get('knowledge') or {}).get('learned_patterns', 0)} learned patterns applied"]
    lines += ["", "## Top findings", ""]
    for finding in [f for f in report["findings"] if f.get("status", "open") not in SUPPRESSED_STATUSES][:25]:
        lines.append(f"- {SEVERITY_ICON[finding['severity']]} **{finding['id']} {_md_escape(finding['title'])}** "
                     f"- `{_md_escape(_where(finding))}`")
    if report["compliance"].get("enabled"):
        lines += ["", "## Compliance overview", "", "| Framework | Score | Pass | Warning | Fail | Manual |",
                  "|---|---:|---:|---:|---:|---:|"]
        for fw in report["compliance"]["frameworks"]:
            s = fw["summary"]
            lines.append(f"| {fw['name']} {fw['version']} | {fw['score']}% | {s['pass']} | {s['warning']} | {s['fail']} | {s['manual']} |")
    if meta.get("notes"):
        lines += ["", "## Notes", ""] + [f"- {_md_escape(n)}" for n in meta["notes"]]
    lines += ["", "---", "Secrets are redacted in every artifact. Generated by Secure Repo - read-only, "
              "non-intrusive analysis."]
    return "\n".join(lines) + "\n"


def markdown_findings(report: Dict, findings: List[Dict], title: str) -> str:
    rules = report["rules"]
    lines = [f"# {title}", "", f"{len(findings)} finding(s).", ""]
    for finding in findings:
        rule = rules.get(finding["rule_id"], {})
        lines += [
            f"## {SEVERITY_ICON[finding['severity']]} {finding['id']} - {_md_escape(finding['title'])}",
            "",
            f"- **Severity:** {finding['severity']}  |  **Confidence:** {finding['confidence']} "
            f"({finding.get('confidence_score', '-')}/100)  |  **Engine:** {finding.get('engine', 'pattern')}  |  "
            f"**Status:** {finding.get('status', 'open')}{'  |  in test code' if finding.get('in_test') else ''}",
            f"- **Location:** `{_md_escape(_where(finding))}`",
            f"- **Rule:** {finding['rule_id']}  |  **Category:** {finding['category']}  |  "
            f"**CWE:** {finding.get('cwe') or '-'}  |  **OWASP:** {finding.get('owasp') or '-'}",
        ]
        if finding.get("snippet"):
            lines += ["", "```", finding["snippet"].replace("```", "'''"), "```"]
        if finding.get("detail"):
            lines += ["", f"**Detail:** {_md_escape(finding['detail'])}"]
        if finding.get("flow"):
            lines += ["", "**Data flow:**", ""]
            lines += [f"{n}. line {step['line']} - {_md_escape(step['label'])}: `{_md_escape(step.get('code', ''))[:160]}`"
                      for n, step in enumerate(finding["flow"], 1)]
        if finding.get("triage"):
            lines += ["", f"**Triage:** {finding.get('status')} - {_md_escape(finding['triage'].get('reason', ''))}"]
        if rule:
            lines += ["", f"**Why it is insecure:** {rule['description']}", "",
                      f"**How to fix:** {rule['recommendation']}"]
            if rule.get("references"):
                lines += ["", "**References:** " + " · ".join(rule["references"])]
        lines.append("")
    return "\n".join(lines)


def markdown_dependencies(report: Dict) -> str:
    dep = report["dependency_summary"]
    lines = ["# Library & dependency analysis", "",
             f"- Libraries: **{dep['total']}** ({dep['direct']} direct / {dep['transitive']} transitive)",
             "- Ecosystems: " + (", ".join(f"{k} ({v})" for k, v in dep["ecosystems"].items()) or "none"),
             "- Manifests: " + (", ".join(f"`{m}`" for m in dep["manifests"]) or "none"),
             f"- Vulnerable libraries: **{dep['vulnerable']}** - unique advisories: **{dep['vulnerabilities']}**",
             f"- Intelligence source: {'OSV.dev + deps.dev' if dep['online'] else 'offline (static checks only)'}",
             "", "## Vulnerable libraries", ""]
    vulnerable = [d for d in report["dependencies"] if d["vulnerabilities"]]
    if not vulnerable:
        lines.append("No known vulnerabilities were found for the resolved library versions.")
    for d in vulnerable:
        lines += [f"### {d['name']} {d['version']} ({d['ecosystem']}{', direct' if d['direct'] else ', transitive'})", "",
                  "| Advisory | Severity | CVSS | Fixed in | Summary |", "|---|---|---:|---|---|"]
        for v in d["vulnerabilities"]:
            alias = next((a for a in v["aliases"] if a.startswith("CVE-")), "")
            ident = v["id"] + (f" / {alias}" if alias else "")
            lines.append(f"| [{ident}]({v['url']}) | {v['severity']} | {v['cvss'] or '-'} | "
                         f"{', '.join(v['fixed']) or '-'} | {_md_escape(v['summary'])} |")
        lines.append("")
    lines += ["## Full inventory", "", "| Library | Version | Ecosystem | Type | Scope | Source | Licenses | Latest | Manifest |",
              "|---|---|---|---|---|---|---|---|---|"]
    for d in report["dependencies"]:
        lines.append(f"| {_md_escape(d['name'])} | {_md_escape(d['version'] or d['spec'])} | {d['ecosystem']} | "
                     f"{'direct' if d['direct'] else 'transitive'} | {d['scope']} | {d['source']} | "
                     f"{_md_escape(', '.join(d['licenses']) or '-')} | {d['latest'] or '-'} | `{d['manifest']}` |")
    return "\n".join(lines) + "\n"


def markdown_quality(report: Dict) -> str:
    analysis = report.get("analysis") or {}
    summary = report["summary"]
    engines = analysis.get("engines") or {}
    lines = ["# Analysis quality", "",
             "Secure Repo combines several engines to keep false positives low:", "",
             "| Layer | What it does | Activity in this scan |", "|---|---|---|",
             f"| Lexical masking | Comments, docstrings and string contents are removed before code patterns run | "
             f"{engines.get('masked_files', 0)} files |",
             f"| Python syntax tree + taint | Resolves imports, inspects arguments and follows untrusted data to sinks | "
             f"{engines.get('python_ast', 0)} files ({engines.get('python_fallback', 0)} fell back to patterns) |",
             f"| JS/TS data flow | Confirms, escalates or discards sink findings | {engines.get('js_flow', 0)} files |",
             f"| Confidence model | Engine, location, and your triage history | min confidence: "
             f"{analysis.get('min_confidence', 'low')} |",
             f"| Triage knowledge | Decisions, learned patterns, rule statistics | "
             f"{'enabled' if analysis.get('learning') else 'disabled'} |", "",
             "## Findings by engine", "", "| Engine | Findings |", "|---|---:|"]
    lines += [f"| {engine} | {count} |" for engine, count in (summary.get("by_engine") or {}).items()]
    lines += ["", f"## Noise discarded automatically ({analysis.get('noise_total', 0)})", "",
              "| Reason | Matches |", "|---|---:|"]
    lines += [f"| {_md_escape(reason)} | {count} |" for reason, count in (analysis.get("noise_filtered") or {}).items()]
    knowledge = analysis.get("knowledge") or {}
    lines += ["", "## Learning & configuration", "",
              f"- Triage decisions applied: {knowledge.get('decisions', 0)}",
              f"- Learned false-positive patterns matched: {knowledge.get('learned_patterns', 0)}",
              f"- Allow-listed by project configuration: {knowledge.get('allowlisted', 0)}",
              f"- Filtered below minimum confidence: {knowledge.get('below_min_confidence', 0)}",
              f"- Project configuration: {analysis.get('config') or 'none (.securerepo.toml)'}",
              f"- Custom rules: {', '.join(analysis.get('custom_rules') or []) or 'none'}", "",
              "## Status of findings", "", "| Status | Findings |", "|---|---:|"]
    lines += [f"| {status} | {count} |" for status, count in (summary.get("by_status") or {}).items()]
    return "\n".join(lines) + "\n" + markdown_not_analyzed(report) + markdown_repo_influence(report)


def markdown_not_analyzed(report: Dict) -> str:
    skipped = (report.get("analysis") or {}).get("not_analyzed")
    if not skipped:
        return ""
    lines = ["", "## What was NOT analyzed", "",
             "These are the blind spots of this scan. Review them before trusting a clean result.", ""]
    directories = skipped.get("directories") or []
    if directories:
        lines += ["### Folders that were not entered", "", "| Folder | Why | Files |", "|---|---|---:|"]
        for entry in directories[:200]:
            count = entry["files"]
            lines.append(f"| `{_md_escape(entry['path'])}` | {_md_escape(entry['reason'])} | "
                         f"{'-' if count is None else (str(count) + ('+' if count >= 5000 else ''))} |")
        lines.append("")
    if skipped.get("unparsed"):
        lines += ["### Dependency manifests that could not be parsed",
                  "", "Their libraries are missing from the inventory, so vulnerabilities in them were not checked.", ""]
        lines += [f"- `{_md_escape(item['path'])}`: {_md_escape(item['error'])}" for item in skipped["unparsed"][:100]] + [""]
    if skipped.get("minified"):
        lines += ["### Minified bundles (reduced analysis: secrets and critical findings only)", ""]
        lines += [f"- `{_md_escape(path)}`" for path in skipped["minified"][:100]] + [""]
    if skipped.get("too_large"):
        lines += ["### Files over the size limit (not read; raise it with --max-file-size)", ""]
        lines += [f"- `{_md_escape(item['path'])}` ({item['bytes']:,} bytes)" for item in skipped["too_large"][:100]] + [""]
    lines += [f"- Binary files skipped: {skipped.get('binary', 0)}",
              f"- Files skipped by type (lockfiles, .min.js, maps, images...): {skipped.get('by_type', 0)}"]
    return "\n".join(lines) + "\n"


def markdown_repo_influence(report: Dict) -> str:
    influence = (report.get("analysis") or {}).get("repo_influence")
    if not influence:
        return ""
    lines = ["", "## Influence of the audited repository on this result", "",
             f"- **Trust:** the audited repository is {'TRUSTED' if influence['trusted'] else 'NOT trusted'} "
             f"({influence['trust_reason']}).",
             f"- **Score with the repository's own content:** {influence.get('score_with_repo_content', '-')} "
             f"({influence.get('grade_with_repo_content', '-')})",
             f"- **Score without it:** {influence.get('score_without_repo_content', '-')} "
             f"({influence.get('grade_without_repo_content', '-')})"]
    if influence.get("material"):
        lines.append("- **WARNING:** the repository's own configuration, triage decisions or inline comments "
                     "change the grade or the score by 10 points or more. Review them before trusting this result.")
    if influence["ignored"]:
        lines += ["", "Ignored (the target is not trusted):"] + [f"- {_md_escape(item)}" for item in influence["ignored"]]
    if influence["disabled_rules"]:
        lines += ["", "Rules disabled by configuration:", "", "| Rule | Findings hidden | Set by |", "|---|---:|---|"]
        lines += [f"| {r['rule_id']} {_md_escape(r['title'])} | {r['hidden']} | {r['from']} |" for r in influence["disabled_rules"]]
    if influence["severity_overrides"]:
        lines += ["", "Severity overrides:", "", "| Rule | From | To | Findings | Set by |", "|---|---|---|---:|---|"]
        lines += [f"| {r['rule_id']} | {r['from_severity']} | {r['to_severity']} | {r['count']} | {r['from']} |"
                  for r in influence["severity_overrides"]]
    excluded = influence["excluded_by_config"]
    if excluded["files"]:
        lines += ["", f"Files excluded from the analysis by configuration: **{excluded['files']}**",
                  ""] + [f"- `{_md_escape(item['pattern'])}` ({item['from']})" for item in excluded["patterns"]]
        lines += [f"  - {_md_escape(path)}" for path in excluded["sample"][:30]]
    counters = [("Allow-listed by configuration", influence["allowlisted"]),
                ("Decisions taken from the repository's shared triage", influence["repo_decisions"]),
                ("Patterns taken from the repository's shared triage", influence["repo_patterns"]),
                ("Inline suppression comments honoured", influence["inline"]),
                ("...of which without a rule ID (silence every rule on the line)", influence["inline_without_rule_id"])]
    lines += [""] + [f"- {label}: {value}" for label, value in counters if value]
    if influence["ignore_file_markers"]:
        lines += ["", "Files carrying a legacy `ignore-file` marker (never honoured, analyzed normally): "
                  + ", ".join(f"`{_md_escape(p)}`" for p in influence["ignore_file_markers"][:20])]
    return "\n".join(lines) + "\n"


def markdown_suppressed(report: Dict) -> str:
    suppressed = [f for f in report["findings"] if f.get("status") in SUPPRESSED_STATUSES]
    lines = ["# Suppressed findings (audit trail)", "",
             f"{len(suppressed)} finding(s) are excluded from the score and the compliance audit.", "",
             "| ID | Rule | Location | Status | Origin | Reason | Author | Date |", "|---|---|---|---|---|---|---|---|"]
    for f in suppressed:
        t = f.get("triage") or {}
        lines.append(f"| {f['id']} | {f['rule_id']} | `{_md_escape(_where(f))}` | {f['status']} | "
                     f"{_md_escape(t.get('origin', ''))} | {_md_escape(t.get('reason', ''))} | "
                     f"{_md_escape(t.get('author', ''))} | {t.get('date', '')} |")
    return "\n".join(lines) + "\n"


def markdown_lockfile_guide(report: Dict) -> str:
    from secure_repo.core.resolver import pinned_snippet

    lock = report.get("lockfile") or {}
    resolution = report["dependency_summary"].get("resolution") or {}
    lines = ["# Lockfile guide", "",
             "A lockfile pins the exact version of every direct and transitive dependency so every build installs "
             "the same, reviewed code. Without it, Secure Repo resolves the versions *virtually*:", "",
             "1. **environment** - versions installed next to the project (node_modules, virtualenv, vendor/);",
             "2. **registry** - the version the package manager would install today for the declared range;",
             "3. **registry-graph** - transitive dependencies of those versions (deps.dev dependency graph).", "",
             "Resolution in this scan: " + (", ".join(f"{k}: {v}" for k, v in resolution.items()) or "n/a"), ""]
    if not lock.get("manifests") and not lock.get("unresolved"):
        lines.append("Every dependency is already pinned by a manifest or a lockfile. Nothing to do.")
        return "\n".join(lines) + "\n"
    for entry in lock.get("manifests", []):
        lines += [f"## `{entry['manifest']}` ({entry['ecosystem']})", "",
                  "Create a real lockfile (run in a trusted environment; the commands avoid install scripts where "
                  "possible):", ""]
        lines += [f"- `{command}`" for command in entry["commands"]]
        snippet = pinned_snippet(entry)
        if snippet:
            lines += ["", "Or pin the resolved versions directly:", "", "```", snippet, "```"]
        lines += ["", "| Package | Declared | Resolved | How | Direct | Vulnerable |", "|---|---|---|---|---|---|"]
        for p in entry["packages"][:400]:
            lines.append(f"| {_md_escape(p['name'])} | `{_md_escape(p['declared'])}` | {p['resolved']} | {p['resolved_by']} | "
                         f"{'yes' if p['direct'] else 'no'} | {'YES' if p['vulnerable'] else 'no'} |")
        lines.append("")
    if lock.get("unresolved"):
        lines += ["## Could not be resolved", "",
                  "Run online (without `--offline`) or install the dependencies locally, then scan again:", ""]
        lines += [f"- {u['name']} `{_md_escape(u['declared'])}` ({u['ecosystem']}, {u['manifest']})" for u in lock["unresolved"]]
    return "\n".join(lines) + "\n"


def markdown_compliance(report: Dict, framework: Dict) -> str:
    icons = {"pass": "✅ PASS", "warning": "⚠️ WARNING", "fail": "❌ FAIL", "manual": "📝 MANUAL"}
    s = framework["summary"]
    lines = [f"# {framework['name']} ({framework['version']}) - compliance evidence", "",
             framework["description"], "",
             f"**Automated score:** {framework['score']}%  -  pass {s['pass']} | warning {s['warning']} | "
             f"fail {s['fail']} | manual {s['manual']}", "",
             f"Target `{report['meta']['target']}` @ `{report['meta'].get('branch') or 'n/a'}` "
             f"commit `{report['meta'].get('commit') or 'n/a'}` - assessed {report['meta']['started_at']} "
             f"by {report['meta'].get('auditor')}", ""]
    for control in framework["controls"]:
        lines += [f"## {icons[control['status']]} {control['id']} - {control['title']}", "", control["description"], ""]
        lines += [f"- {_md_escape(e)}" for e in control["evidence"]]
        if control["findings"]:
            lines.append(f"- Linked findings: {', '.join(control['findings'][:30])}")
        lines.append("")
    lines += ["---", f"> {report['compliance']['disclaimer']}"]
    return "\n".join(lines) + "\n"


_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def csv_safe(value):
    """Neutralize spreadsheet formulas: cells starting with = + - @ (or tab/CR) are prefixed with a quote.

    File names, code snippets and package names come from the audited repository, which is not trusted: a file
    called ``=HYPERLINK(...)`` must not become a formula when the analyst opens the CSV in Excel or LibreOffice.
    """
    if isinstance(value, str) and value.startswith(_FORMULA_PREFIXES):
        return "'" + value
    return value


def _csv_row(writer, row) -> None:
    writer.writerow([csv_safe(cell) for cell in row])


def findings_csv(report: Dict) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    _csv_row(writer, ["id", "severity", "title", "rule_id", "category", "cwe", "owasp", "file", "line", "confidence",
                      "confidence_score", "engine", "status", "triage_reason", "in_test", "fingerprint", "detail",
                      "snippet"])
    for f in report["findings"]:
        _csv_row(writer, [f["id"], f["severity"], f["title"], f["rule_id"], f["category"], f["cwe"], f["owasp"],
                         f["file"], f["line"], f["confidence"], f.get("confidence_score", ""), f.get("engine", ""),
                         f.get("status", "open"), (f.get("triage") or {}).get("reason", ""), f["in_test"],
                         f.get("fingerprint", ""), f["detail"], f["snippet"]])
    return buffer.getvalue()


def dependencies_csv(report: Dict) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    _csv_row(writer, ["name", "version", "spec", "ecosystem", "direct", "scope", "source", "locked", "manifests",
                     "vulnerabilities", "max_severity", "advisories", "licenses", "latest", "resolved_by", "parent",
                     "issues"])
    for d in report["dependencies"]:
        _csv_row(writer, [d["name"], d["version"] or "", d["spec"], d["ecosystem"], d["direct"], d["scope"], d["source"],
                         d["locked"], ";".join(d["manifests"]), len(d["vulnerabilities"]), d["max_severity"] or "",
                         ";".join(v["id"] for v in d["vulnerabilities"]), ";".join(d["licenses"]), d["latest"] or "",
                         d.get("resolved_by") or "", d.get("parent") or "", ";".join(d["issues"])])
    return buffer.getvalue()


def sarif(report: Dict) -> Dict:
    rules = []
    for rule_id, rule in report["rules"].items():
        rules.append({
            "id": rule_id, "name": rule["title"],
            "shortDescription": {"text": rule["title"]},
            "fullDescription": {"text": rule["description"]},
            "help": {"text": rule["recommendation"], "markdown": f"**Fix:** {rule['recommendation']}"},
            "helpUri": (rule.get("references") or [""])[0] or None,
            "properties": {"tags": ["security", rule["category"]] + ([rule["cwe"]] if rule["cwe"] else []),
                           "security-severity": SARIF_SCORE[rule["severity"]], "precision": rule["confidence"]},
        })
    results = []
    for f in report["findings"]:
        location = {"physicalLocation": {"artifactLocation": {"uri": f["file"] if f["file"] not in ("", ".") else "."}}}
        if f.get("line"):
            location["physicalLocation"]["region"] = {"startLine": f["line"]}
        result = {
            "ruleId": f["rule_id"], "level": SARIF_LEVEL[f["severity"]],
            "message": {"text": f"{f['title']}. {f['detail']}".strip()},
            "locations": [location],
            "partialFingerprints": {"secureRepo/v1": f.get("fingerprint", "")},
            "properties": {"severity": f["severity"], "id": f["id"], "security-severity": SARIF_SCORE[f["severity"]],
                           "confidence": f.get("confidence"), "engine": f.get("engine"), "status": f.get("status")},
        }
        if f.get("flow"):
            result["codeFlows"] = [{"threadFlows": [{"locations": [
                {"location": {"physicalLocation": {"artifactLocation": {"uri": f["file"]},
                                                   "region": {"startLine": max(1, step["line"])}},
                              "message": {"text": step["label"]}}} for step in f["flow"]]}]}]
        if f.get("status") in SUPPRESSED_STATUSES + ("accepted_risk",):
            result["suppressions"] = [{"kind": "external", "status": "accepted",
                                       "justification": f"{f['status']}: {(f.get('triage') or {}).get('reason', '')}"}]
        results.append(result)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Secure Repo", "version": report["tool"]["version"],
                                "informationUri": "https://github.com/Wissen01720/Secure_Repo", "rules": rules}},
            "results": results,
            "versionControlProvenance": [{"repositoryUri": report["meta"].get("remote") or report["meta"]["target"],
                                          "revisionId": report["meta"].get("commit") or None,
                                          "branch": report["meta"].get("branch") or None}],
        }],
    }


PURL_TYPE = {"PyPI": "pypi", "npm": "npm", "Go": "golang", "crates.io": "cargo", "RubyGems": "gem",
             "Packagist": "composer", "Maven": "maven", "NuGet": "nuget", "Pub": "pub", "Hex": "hex"}


def _purl(dep: Dict) -> str:
    kind = PURL_TYPE.get(dep["ecosystem"], "generic")
    name = dep["name"]
    if kind == "maven" and ":" in name:
        group, artifact = name.split(":", 1)
        name = f"{group}/{artifact}"
    elif kind == "npm" and name.startswith("@"):
        name = "%40" + name[1:]
    return f"pkg:{kind}/{name}" + (f"@{dep['version']}" if dep.get("version") else "")


def cyclonedx(report: Dict) -> Dict:
    components, vulnerabilities = [], []
    for dep in report["dependencies"]:
        ref = _purl(dep)
        component = {"type": "library", "bom-ref": ref, "name": dep["name"], "version": dep.get("version") or "",
                     "purl": ref, "scope": "required" if dep["scope"] == "runtime" else "optional",
                     "properties": [{"name": "secure-repo:direct", "value": str(dep["direct"]).lower()},
                                    {"name": "secure-repo:manifest", "value": dep["manifest"]}]}
        if dep.get("licenses"):
            component["licenses"] = [{"expression": " OR ".join(dep["licenses"])}]
        components.append(component)
        for vuln in dep.get("vulnerabilities", []):
            vulnerabilities.append({
                "bom-ref": f"{vuln['id']}::{ref}", "id": vuln["id"], "source": {"name": "OSV", "url": vuln["url"]},
                "ratings": [{"severity": vuln["severity"], **({"score": vuln["cvss"], "method": "CVSSv3"} if vuln["cvss"] else {})}],
                "description": vuln["summary"], "affects": [{"ref": ref}],
                "recommendation": ("Upgrade to " + ", ".join(vuln["fixed"])) if vuln["fixed"] else "",
            })
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
        "metadata": {"timestamp": report["meta"]["finished_at"],
                     "tools": [{"vendor": "Secure Repo", "name": "secure-repo", "version": report["tool"]["version"]}],
                     "component": {"type": "application", "name": report["meta"]["name"],
                                   "version": (report["meta"].get("commit") or "")[:12] or "unversioned"}},
        "components": components, "vulnerabilities": vulnerabilities,
    }


def languages_markdown(report: Dict) -> str:
    lines = ["# Languages", "", "| Language | Files | Lines | Size (KB) |", "|---|---:|---:|---:|"]
    for name, info in report["languages"].items():
        lines.append(f"| {name} | {info['files']} | {info['lines']:,} | {info['bytes'] / 1024:.1f} |")
    return "\n".join(lines) + "\n"
