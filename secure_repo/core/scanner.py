"""Scan orchestrator: runs every analysis stage and assembles the report.

Analysis layers applied to each source file:

1. **Lexical masking** - comments and string literals are blanked (offsets preserved) so code
   patterns never match inside comments, docstrings or messages.
2. **Semantic engines** - Python is parsed into a syntax tree with taint tracking; JavaScript /
   TypeScript get a data-flow pass that confirms, escalates or discards pattern findings.
3. **Patterns** - 160+ rules for every other language and for configuration/IaC/CI files.
4. **Confidence & learning** - each finding is scored and the triage knowledge base (decisions,
   learned false-positive patterns, per-rule statistics) plus the project configuration are applied.

The work is split across mixins: scan_analysis (files), scan_dependencies (libraries), scan_quality (trust,
configuration, baseline, hygiene); this module orchestrates them and builds the report.
"""

from __future__ import annotations

import os
import platform
import time
import urllib.error
from dataclasses import replace
from datetime import datetime, UTC
from typing import Any

from secure_repo import __author__, __version__
from secure_repo.core import (
    checks,
    compliance,
    gitops,
    intel,
    netio,
    resolver,
)
from secure_repo.core import summary as summarymod
from secure_repo.core.config import ProjectConfig
from secure_repo.core.events import EventBus
from secure_repo.core.models import OWASP_2025, OWASP_TOP10, OWASP_TOP10_2025, SEVERITY_RANK, SUPPRESSED_STATUSES
from secure_repo.core.rules import PATTERN_RULES, RULES
from secure_repo.core.scan_analysis import AnalysisMixin
from secure_repo.core.scan_common import MAX_AUTO_JOBS, ScanCancelled, ScanOptions, load_baseline  # noqa: F401
from secure_repo.core.scan_dependencies import DependencyMixin
from secure_repo.core.scan_quality import QualityMixin
from secure_repo.core.walker import FileInfo, StructureTree, enumerate_files
from secure_repo.core.workspace import Target, Workspace, prepare_workspace

_WORKER: dict[str, Scanner] = {}


def _init_worker(options: ScanOptions, config: ProjectConfig, trusted: bool) -> None:
    """Runs once in every worker process: a private scanner configured like the parent's (no learning, no events)."""
    scanner = Scanner(replace(options, learning=False), EventBus(), knowledge=None)
    scanner.config, scanner.trusted = config, trusted
    scanner.rules = list(PATTERN_RULES) + config.custom_rules
    scanner.path_rules = [r for r in scanner.rules if r.path]
    _WORKER["scanner"] = scanner


def _worker_process(info: FileInfo) -> dict:
    return _WORKER["scanner"]._process_file(info, collect=True)


class Scanner(AnalysisMixin, DependencyMixin, QualityMixin):
    # ------------------------------------------------------------------ main
    def run(self, target: Target, interactive: bool = False, write_reports: bool = True) -> tuple[dict, str | None]:
        # Every scan owns its network session (settings, counters, notes): two scans at once never mix them.
        self.network = netio.NetworkSession(netio.NetworkSettings(ca_bundle=self.options.ca_bundle,
                                                                  cache=self.options.cache))
        with netio.active(self.network):
            return self._run(target, interactive, write_reports)

    def _run(self, target: Target, interactive: bool, write_reports: bool) -> tuple[dict, str | None]:
        from secure_repo.report.writer import write_reports as write_all  # local import avoids cycles

        started = time.time()
        started_iso = datetime.now(UTC).isoformat(timespec="seconds")
        bus = self.bus
        workspace: Workspace | None = None
        try:
            bus.stage("acquire", "start")
            bus.log(f"Target: {target.location} ({'remote URL' if target.kind == 'remote' else 'local path'})")
            workspace = prepare_workspace(target, bus, interactive=interactive)
            bus.stage("acquire", "done", f"{workspace.mode} @ {workspace.branch or 'n/a'}")
            self._check_cancel()
            self._load_configuration(workspace)

            bus.stage("enumerate", "start")
            files = enumerate_files(workspace.path, self.options.exclude + self.config.exclude,
                                    skipped=self.not_analyzed["directories"])
            excluded_by_config: list[str] = []
            if self.config.exclude:  # which files did the configuration take out of the analysis?
                kept = {f.rel for f in files}
                excluded_by_config = [f.rel for f in enumerate_files(workspace.path, self.options.exclude)
                                      if f.rel not in kept]
                bus.log(f"The configuration excludes {len(excluded_by_config)} file(s) from the analysis "
                        f"({', '.join(self.config.exclude[:6])}{' ...' if len(self.config.exclude) > 6 else ''})", "warn")
            tree = StructureTree(workspace.name, files)
            bus.emit("structure", tree=tree.to_dict(), files=len(files))
            directories = sum(1 for node in tree.index.values() if node["type"] == "dir") - 1
            bus.log(f"Mapped {len(files)} files in {directories} directories", "ok")
            bus.stage("enumerate", "done", f"{len(files)} files")

            analyzed_files = files
            if self.options.since:
                analyzed_files = self._files_since(workspace, files)
            bus.stage("analyze", "start")
            stats = {"scanned": 0, "skipped": 0, "lines": 0, "languages": {}}
            self._stage_analyze(analyzed_files, tree, stats)
            engines = self.engine_stats
            bus.log(f"Engines: {engines['python_ast']} Python syntax trees, {engines['js_flow']} JS/TS data-flow passes, "
                    f"{engines['masked_files']} files lexically masked; {sum(self.noise.values())} noisy matches discarded", "ok")
            bus.stage("analyze", "done", f"{stats['scanned']} files analyzed, {len(self.findings)} findings")

            bus.stage("dependencies", "start")
            inventory, issues, manifests = self._stage_dependencies(analyzed_files)
            direct = sum(1 for d in inventory if d.direct)
            bus.stage("dependencies", "done", f"{len(inventory)} libraries ({direct} direct) in {len(manifests)} manifests")

            self._mark_private(inventory)
            bus.stage("resolve", "start")
            resolution = self._stage_resolve(inventory, workspace.path)
            unresolved = sum(1 for d in inventory if d.direct and not d.version and d.source == "registry")
            if any(resolution.values()) or unresolved:
                bus.stage("resolve", "done", f"environment {resolution['environment']} · registry {resolution['registry']}"
                                             f" · graph +{resolution['graph']} · unresolved {unresolved}")
            else:
                bus.stage("resolve", "skip", "every version already pinned" if inventory else "no dependencies")
            self._dependency_findings(inventory, issues)
            self._runtime_findings(analyzed_files)

            online = not self.options.offline
            queried = 0
            intel_error = ""
            bus.stage("intel", "start")
            if not online:
                bus.log("Offline mode - skipping OSV.dev and deps.dev lookups", "warn")
                bus.stage("intel", "skip", "offline mode")
            elif not inventory:
                bus.stage("intel", "skip", "no dependencies")
            else:
                try:
                    queried, vulnerable = intel.osv_lookup(inventory, bus)
                    if self.options.enrich and not self.options.no_registry:
                        intel.depsdev_enrich(inventory, bus, limit=self.options.max_enrich)
                    self._vulnerability_findings(inventory)
                    self._range_findings(inventory)
                    if self.options.check_confusion:
                        self._confusion_findings(inventory)
                    bus.stage("intel", "done", f"{queried} versions checked, {vulnerable} vulnerable")
                except (urllib.error.URLError, OSError, ValueError) as exc:
                    intel_error = str(getattr(exc, "reason", exc))
                    bus.log(f"Vulnerability intelligence unavailable: {intel_error}", "warn")
                    self._vulnerability_findings(inventory)
                    bus.stage("intel", "skip", "network unavailable")

            self.not_analyzed["intel"] = list(self.network.stats.notes)
            bus.stage("hygiene", "start")
            hygiene = self._stage_hygiene(files, workspace.path, bool(inventory))
            bus.stage("hygiene", "done", f"{sum(hygiene.values())}/{len(hygiene)} practices present")

            meta: dict[str, Any] = {
                "name": workspace.name, "target": target.location, "target_kind": target.kind,
                "branch": workspace.branch, "commit": workspace.commit, "mode": workspace.mode,
                "remote": checks.redact_text(workspace.remote), "started_at": started_iso,
                "platform": f"{platform.system()} {platform.release()} ({platform.machine()})",
                "python": platform.python_version(), "git": gitops.git_version(),
                "auditor": self.options.auditor or "not specified",
                "options": {"offline": self.options.offline, "compliance": self.options.compliance,
                            "frameworks": compliance.resolve_frameworks(self.options.frameworks)
                            if self.options.compliance else [],
                            "include_tests": self.options.include_tests, "min_confidence": self.options.min_confidence,
                            "learning": self.options.learning, "max_file_size": self.options.max_file_size,
                            "exclude": self.options.exclude + self.config.exclude,
                            "trust_repo_config": self.trusted, "trust_reason": self.trust_reason},
                "notes": workspace.notes + ([f"Vulnerability intelligence unavailable: {intel_error}"] if intel_error else []),
            }

            # Quality pipeline: fingerprints, confidence, triage knowledge, configuration --------------
            findings = [f.to_dict() for f in self.findings]
            quality = self._apply_quality(findings, meta, workspace.path)
            baseline_info = self._apply_baseline(findings)
            if baseline_info:
                meta["baseline"] = baseline_info
            influence = self._repo_influence(findings, workspace, excluded_by_config)
            if quality["decisions"] or quality["learned_patterns"]:
                bus.log(f"Triage knowledge applied: {quality['decisions']} decision(s), "
                        f"{quality['learned_patterns']} learned false-positive pattern match(es)", "ok")
            findings.sort(key=lambda f: (f["status"] in SUPPRESSED_STATUSES, SEVERITY_RANK.get(f["severity"], 9),
                                         f["file"], f["line"], f["rule_id"]))
            for number, finding in enumerate(findings, 1):
                finding["id"] = f"SR-{number:04d}"

            bus.stage("compliance", "start")
            bus.stage("scoring", "start")
            finished = time.time()
            meta["finished_at"] = datetime.now(UTC).isoformat(timespec="seconds")
            meta["duration_seconds"] = round(finished - started, 2)
            vulnerable_deps = [d for d in inventory if d.vulnerabilities]
            ecosystems: dict[str, int] = {}
            for dep in inventory:
                ecosystems[dep.ecosystem] = ecosystems.get(dep.ecosystem, 0) + 1
            direct = sum(1 for d in inventory if d.direct)
            inventory.sort(key=lambda d: (not d.vulnerabilities, not d.direct, d.ecosystem, d.name.lower()))
            report: dict[str, Any] = {
                "schema": "secure-repo/report@1",
                "tool": {"name": "Secure Repo", "version": __version__, "author": __author__, "rules": len(RULES)},
                "meta": meta,
                "summary": {"files_total": len(files), "files_scanned": stats["scanned"],
                            "files_skipped": stats["skipped"], "lines": stats["lines"]},
                "findings": findings,
                "rules": {},
                "owasp": OWASP_TOP10,
                "owasp_2025": OWASP_2025, "owasp_top10_2025": OWASP_TOP10_2025,
                "dependencies": [d.to_dict() for d in inventory],
                "dependency_summary": {
                    "total": len(inventory), "direct": direct, "transitive": len(inventory) - direct,
                    "ecosystems": ecosystems, "manifests": manifests, "vulnerable": len(vulnerable_deps),
                    "vulnerabilities": len({v["id"] for d in vulnerable_deps for v in d.vulnerabilities}),
                    "queried": queried, "online": online and not intel_error,
                    "resolution": resolver.summarize(inventory),
                },
                "lockfile": resolver.virtual_lockfile(inventory),
                "analysis": {
                    "engines": dict(self.engine_stats), "noise_filtered": dict(sorted(self.noise.items())),
                    "noise_total": sum(self.noise.values()), "knowledge": quality,
                    "learning": self.options.learning, "config": os.path.basename(self.config.source) if self.config.source else None,
                    "custom_rules": [r.id for r in self.config.custom_rules], "min_confidence": self.options.min_confidence,
                    "repo_influence": influence,
                    "not_analyzed": self.not_analyzed,
                    "network": self.network.stats.to_dict(),
                },
                "structure": tree.to_dict(),
                "languages": stats["languages"],
                "hygiene": hygiene,
                "compliance": {"enabled": False, "frameworks": []},
            }
            summarymod.finalize(report, {r.id: r.to_dict() for r in self.config.custom_rules})
            if report["compliance"].get("enabled"):
                names = ", ".join(f"{fw['name']} {fw['score']}%" for fw in report["compliance"]["frameworks"])
                bus.stage("compliance", "done", names)
            else:
                bus.stage("compliance", "skip", "disabled")
            bus.stage("scoring", "done", f"score {report['summary']['score']}/100 grade {report['summary']['grade']}"
                                         + (f" · {report['summary']['suppressed']} suppressed" if report['summary']['suppressed'] else ""))

            report_dir = None
            if write_reports:
                bus.stage("report", "start")
                report_dir = write_all(report, self.options.output_dir, bus, tree_text=tree.render_text(),
                                       log_lines=self.log_lines)
                bus.stage("report", "done", report_dir)
            else:
                bus.stage("report", "skip", "report writing disabled")
            bus.emit("done", summary=report["summary"], report_dir=report_dir)
            return report, report_dir
        except ScanCancelled as exc:
            bus.emit("error", message=str(exc))
            raise
        except Exception as exc:
            bus.log(f"Scan failed: {exc}", "error")
            bus.emit("error", message=str(exc))
            raise
        finally:
            if workspace is not None:
                workspace.cleanup()
