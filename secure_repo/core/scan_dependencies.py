"""Dependency stages: inventory, private packages, version resolution and findings."""

from __future__ import annotations

import fnmatch
import os
import urllib.error

from secure_repo.core import checks, intel, resolver
from secure_repo.core import deps as depmod
from secure_repo.core.models import SEVERITY_RANK, Dependency
from secure_repo.core.scan_base import ScannerBase
from secure_repo.core.rules import RULES_BY_ID
from secure_repo.core.walker import FileInfo, read_text


class DependencyMixin(ScannerBase):
    def _stage_dependencies(self, files: list[FileInfo]) -> tuple[list[Dependency], list[depmod.ParseIssue], list[str]]:
        manifests = [f for f in files if depmod.is_manifest(f.rel)]
        issues: list[depmod.ParseIssue] = []
        parsed: list[tuple[Dependency, bool]] = []
        for index, info in enumerate(manifests, 1):
            self._check_cancel()
            found = depmod.parser_for(info.rel)
            if found is None:
                continue
            parser, is_lock = found
            text = read_text(info, 50 * 1024 * 1024)
            if text is None:
                continue
            problem = depmod.syntax_error(info.rel, text)
            if problem:
                # A damaged manifest must not look like "no dependencies": say so in the report.
                self.not_analyzed["unparsed"].append({"path": info.rel, "error": problem})
                self.bus.log(f"{info.rel} is not valid ({problem}); its dependencies may be missing", "warn")
            try:
                result = parser(text, info.rel, issues)
            except Exception as exc:  # malformed manifest - report and continue
                self.bus.log(f"Could not parse {info.rel}: {exc}", "warn")
                if not problem:
                    self.not_analyzed["unparsed"].append({"path": info.rel, "error": f"parser error: {str(exc)[:120]}"})
                continue
            for dep in result:
                if is_lock:
                    dep.direct = dep.direct and parser is depmod.parse_nuget_lock
                    dep.resolved_by = "lockfile"
                elif dep.version:
                    dep.resolved_by = "manifest"
                parsed.append((dep, is_lock))
            ecosystems = sorted({d.ecosystem for d in result}) or ["-"]
            self.bus.log(f"{info.rel} -> {len(result)} libraries ({', '.join(ecosystems)})", "ok")
            self.bus.progress("dependencies", index, len(manifests), info.rel)

        # A requirements file where every registry dependency is pinned (==) behaves like a lockfile.
        by_manifest: dict[str, list[Dependency]] = {}
        for dep, _is_lock in parsed:
            by_manifest.setdefault(dep.manifest, []).append(dep)
        pinned_requirements = {
            manifest for manifest, items in by_manifest.items()
            if (depmod.parser_for(manifest) or (None, False))[0] is depmod.parse_requirements
            and all(d.version for d in items if d.source == "registry")
        }

        # Link lockfile versions to direct declarations.
        lock_index: dict[tuple[str, str, str], list[str]] = {}
        lock_dirs: dict[str, set] = {}
        for dep, is_lock in parsed:
            if is_lock or dep.manifest in pinned_requirements:
                directory = os.path.dirname(dep.manifest)
                lock_index.setdefault((dep.ecosystem, directory, depmod.normalize_name(dep.ecosystem, dep.name)), []).append(dep.version or "")
                lock_dirs.setdefault(dep.ecosystem, set()).add(directory)

        def ancestors(path: str) -> list[str]:
            chain, current = [], os.path.dirname(path)
            while True:
                chain.append(current)
                if not current:
                    return chain
                current = os.path.dirname(current)

        for dep, is_lock in parsed:
            if is_lock:
                continue
            for directory in ancestors(dep.manifest):
                if directory in lock_dirs.get(dep.ecosystem, set()):
                    dep.locked = True
                    versions = lock_index.get((dep.ecosystem, directory, depmod.normalize_name(dep.ecosystem, dep.name)))
                    if versions and not dep.version and dep.source == "registry":
                        dep.version = sorted(set(versions))[0]
                        dep.resolved_by = "lockfile"
                    break

        inventory: dict[tuple[str, str, str], Dependency] = {}
        for dep, _is_lock in sorted(parsed, key=lambda item: item[1]):
            identity = dep.version or f"spec:{dep.spec}"
            key = (dep.ecosystem, depmod.normalize_name(dep.ecosystem, dep.name), identity)
            existing = inventory.get(key)
            if existing is None:
                dep.manifests = [dep.manifest]
                inventory[key] = dep
            else:
                if dep.manifest not in existing.manifests:
                    existing.manifests.append(dep.manifest)
                existing.direct = existing.direct or dep.direct
                existing.locked = existing.locked or dep.locked
        return list(inventory.values()), issues, [m.rel for m in manifests]

    def _mark_private(self, inventory: list[Dependency]) -> int:
        """Flag dependencies whose names must never be sent anywhere (``--private`` and ``[intel] private``)."""
        patterns = [p.lower() for p in list(self.options.private) + list(self.config.intel_private) if p]
        if not patterns:
            return 0
        count = 0
        for dep in inventory:
            if any(fnmatch.fnmatchcase(dep.name.lower(), pattern) for pattern in patterns):
                dep.private = True
                count += 1
        if count:
            self.bus.log(f"{count} private package(s) are excluded from every network lookup", "ok")
        return count

    def _confusion_findings(self, inventory: list[Dependency]) -> None:
        """Opt-in: a private package name that also exists in the public registry invites dependency confusion."""
        rule = RULES_BY_ID["SR-DEP-010"]
        for dep in inventory:
            if not (dep.private and dep.direct and dep.source == "registry"):
                continue
            if intel.exists_publicly(dep) is True:
                detail = (f"'{dep.name}' is declared as private, but a package with that exact name exists in the public "
                          f"{dep.ecosystem} registry. If a build resolves it from the public index (a missing "
                          f"--index-url, a proxy without scoping), an attacker's package is installed instead.")
                self._add(self._finding_from_rule(rule, dep.manifest, dep.line, dep.name, detail=detail,
                                                  title=f"Private package name exists publicly: {dep.name}",
                                                  extra={"package": dep.name, "ecosystem": dep.ecosystem}))
                dep.issues.append("Private name also exists in the public registry")

    def _stage_resolve(self, inventory: list[Dependency], root: str) -> dict[str, int]:
        counts = {"environment": 0, "registry": 0, "graph": 0}
        if not self.options.resolve_versions or not inventory:
            return counts
        counts["environment"] = resolver.resolve_from_environment(inventory, root)
        if counts["environment"]:
            self.bus.log(f"{counts['environment']} version(s) resolved from the installed environment", "ok")
        if not self.options.offline and not self.options.no_registry:
            try:
                counts["registry"] = resolver.resolve_from_registry(inventory, self.bus, limit=self.options.max_registry)
                added = resolver.resolve_graph(inventory, self.bus, limit=self.options.max_graph)
                inventory.extend(added)
                counts["graph"] = len(added)
            except (urllib.error.URLError, OSError, ValueError) as exc:
                self.bus.log(f"Registry resolution unavailable: {getattr(exc, 'reason', exc)}", "warn")
        return counts

    def _dependency_findings(self, inventory: list[Dependency], issues: list[depmod.ParseIssue]) -> None:
        unlocked: dict[str, list[Dependency]] = {}
        for dep in inventory:
            if dep.direct and not dep.locked and dep.source == "registry" and dep.resolved_by not in ("manifest", "lockfile") \
                    and dep.ecosystem not in ("Go",) and dep.spec not in ("managed",):
                unlocked.setdefault(dep.manifest, []).append(dep)
            if dep.source in ("git", "url"):
                rule = RULES_BY_ID["SR-DEP-005"]
                self._add(self._finding_from_rule(rule, dep.manifest, dep.line, f"{dep.name} -> {checks.redact_text(dep.spec)}",
                                                  detail=f"{dep.name} is installed from {dep.source.upper()} source "
                                                         f"'{checks.redact_text(dep.spec)}'.",
                                                  extra={"package": dep.name, "ecosystem": dep.ecosystem}))
            bad = intel.known_bad(dep)
            if bad:
                rule = RULES_BY_ID[bad[0]]
                self._add(self._finding_from_rule(rule, dep.manifest, dep.line, f"{dep.name} {dep.version or dep.spec}",
                                                  detail=bad[1], title=f"{rule.title}: {dep.name}",
                                                  extra={"package": dep.name, "ecosystem": dep.ecosystem}))
                dep.issues.append(bad[1])
        for manifest, items in unlocked.items():
            resolved = [d for d in items if d.version]
            pending = [d for d in items if not d.version]
            detail = f"{len(items)} dependencies use version ranges and no lockfile pins them."
            if resolved:
                sample = ", ".join(f"{d.name} {d.spec} -> {d.version} ({d.resolved_by})" for d in resolved[:6])
                detail += (f" Secure Repo resolved {len(resolved)} of them virtually ({sample}{' ...' if len(resolved) > 6 else ''})"
                           " and checked those versions; see dependencies/lockfile-guide.md to create a real lockfile.")
            if pending:
                detail += " Not resolvable: " + ", ".join(d.name for d in pending[:10]) + (" ..." if len(pending) > 10 else "") + "."
            rule = RULES_BY_ID["SR-DEP-004"]
            self._add(self._finding_from_rule(rule, manifest, 0, manifest, detail=detail,
                                              extra={"unlocked": [d.name for d in items]}))
            for dep in items:
                dep.issues.append("Version range without lockfile" + (f" (resolved to {dep.version})" if dep.version else ""))
        for issue in issues:
            rule = RULES_BY_ID[issue.rule_id]
            self._add(self._finding_from_rule(rule, issue.manifest, issue.line,
                                              checks.redact_text(issue.snippet or issue.detail),
                                              detail=checks.redact_text(issue.detail)))

    def _vulnerability_findings(self, inventory: list[Dependency]) -> None:
        rule = RULES_BY_ID["SR-DEP-001"]
        for dep in inventory:
            if dep.vulnerabilities:
                worst = min((v["severity"] for v in dep.vulnerabilities), key=lambda s: SEVERITY_RANK.get(s, 9))
                ids = [v["aliases"][0] if v["aliases"] and v["aliases"][0].startswith("CVE-") else v["id"]
                       for v in dep.vulnerabilities]
                fixes = sorted({f for v in dep.vulnerabilities for f in v["fixed"]})
                count = len(dep.vulnerabilities)
                how = {"registry": " (version resolved from the declared range)", "environment": " (installed version)",
                       "registry-graph": f" (transitive, pulled in by {dep.parent})"}.get(dep.resolved_by or "", "")
                detail = (f"{dep.name} {dep.version}{how} ({dep.ecosystem}) is affected by {count} known "
                          f"vulnerabilit{'y' if count == 1 else 'ies'}: {', '.join(ids[:8])}"
                          f"{' ...' if len(ids) > 8 else ''}.")
                if fixes:
                    detail += f" Fixed in: {', '.join(fixes[:5])}."
                for vuln in dep.vulnerabilities:
                    if vuln["id"].startswith("MAL-"):
                        dep.issues.append("Flagged as malicious by OSV")
                self._add(self._finding_from_rule(
                    rule, dep.manifest, dep.line if dep.direct else 0, f"{dep.name}@{dep.version}", detail=detail,
                    severity=worst, title=f"Vulnerable library: {dep.name}@{dep.version}",
                    extra={"package": dep.name, "version": dep.version, "ecosystem": dep.ecosystem,
                           "direct": dep.direct, "vulnerabilities": dep.vulnerabilities, "fixed": fixes,
                           "resolved_by": dep.resolved_by}))
            if dep.latest and dep.version:
                current, latest = intel.major(dep.version), intel.major(dep.latest)
                if current is not None and latest is not None and latest > current:
                    self._add(self._finding_from_rule(
                        RULES_BY_ID["SR-DEP-007"], dep.manifest, dep.line, f"{dep.name} {dep.version} -> {dep.latest}",
                        detail=f"{dep.name} {dep.version} is {latest - current} major version(s) behind {dep.latest}.",
                        title=f"Outdated library: {dep.name}", extra={"package": dep.name, "ecosystem": dep.ecosystem}))
            if dep.licenses:
                risky = [lic for lic in dep.licenses if intel.COPYLEFT_RE.search(lic) or lic.lower() == "non-standard"]
                if risky:
                    self._add(self._finding_from_rule(
                        RULES_BY_ID["SR-DEP-008"], dep.manifest, dep.line, f"{dep.name}: {', '.join(dep.licenses)}",
                        detail=f"{dep.name} is licensed under {', '.join(dep.licenses)}.",
                        title=f"License review: {dep.name}", extra={"package": dep.name, "ecosystem": dep.ecosystem}))

    def _range_findings(self, inventory: list[Dependency]) -> None:
        candidates = [d for d in inventory if d.resolved_by == "registry" and d.range_lowest
                      and d.range_lowest != d.version and not d.vulnerabilities]
        if not candidates:
            return
        found = intel.osv_vulnerability_ids([(d.ecosystem, d.name, str(d.range_lowest)) for d in candidates
                                             if not d.private])
        rule = RULES_BY_ID["SR-DEP-009"]
        for dep in candidates:
            ids = found.get((dep.ecosystem, dep.name, str(dep.range_lowest)))
            if not ids:
                continue
            self._add(self._finding_from_rule(
                rule, dep.manifest, dep.line, f"{dep.name} {dep.spec}",
                detail=(f"'{dep.name} {dep.spec}' resolves today to {dep.version} (not affected), but the range also "
                        f"admits {dep.range_lowest}, affected by {len(ids)} advisor{'y' if len(ids) == 1 else 'ies'} "
                        f"({', '.join(ids[:5])}). Raise the minimum version."),
                title=f"Range admits vulnerable releases: {dep.name}",
                extra={"package": dep.name, "ecosystem": dep.ecosystem, "range_lowest": dep.range_lowest, "advisories": ids}))
            dep.issues.append(f"Range admits vulnerable {dep.range_lowest}")
